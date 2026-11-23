#!/usr/bin/env python3
"""Inspect or create patched copies of reviewed Antigravity macOS ARM64 builds."""
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile

class Refused(Exception):
    pass

@dataclass(frozen=True)
class Edit:
    offset: int
    before: bytes
    after: bytes
    context: bytes
    function: str

@dataclass(frozen=True)
class Profile:
    target: str
    version: str
    size: int
    sha256: str
    text_start: int
    text_end: int
    edits: tuple

CLI = Profile("cli", "1.5.15", 229617904,
    "8097b24de18aba93324ee24d0d3f060906c58ba58562f4f1bd66f380906056a2",
    0x11c0, 0x3bea848, (
        Edit(0x2461364, bytes.fromhex("08204039"), bytes.fromhex("28008052"),
             bytes.fromhex("1f7d01a91f7d02a91f7d03a9400900b4082040390809003708a444a9aa5404b04a612591"),
             "backend.IneligibilityFromResult"),
        Edit(0x2497e28, bytes.fromhex("02204039"), bytes.fromhex("22008052"),
             bytes.fromhex("e2031faae04300f9811500b5800c00b402204039420c00374425ff97e0870ea9e28f0fa9"),
             "backend.(*ServerBackend).handleAuthResult.func1"),
    ))
APP = Profile("app", "2.34.0", 196898624,
    "bf66ad9f32ea50cf47686b3a4265cdd596d7c91a34de362f82264a4f52be4a87",
    0xf80, 0x3457388, (
        Edit(0x25d3ec0, bytes.fromhex("03204039a3010036"),
             bytes.fromhex("2300805203200039"),
             bytes.fromhex("63c02791e6031faa66010094e10100b503204039a3010036e31348a9031006a9bba604b063a343b9"),
             "authclient.(*PersonalAuthValidator).Validate"),
    ))
PROFILES = {"cli": CLI, "app": APP}
APP_BINARY = Path("Contents/Resources/bin/language_server")
APP_INFO_SHA256 = "66448e4cc32f3c093944e15668709689197679c4ca46faa973515f5d4d874d35"
APP_ASAR_SHA256 = "8934adef0622c9271c92eea950a71848764a66f7b10023ccbd82e54b959adb0e"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def file_digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()

def read_source(path, profile=CLI):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != profile.size:
            raise Refused("Unsupported file type or size.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read()
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise Refused("Source changed while reading.")
        return data
    finally:
        os.close(fd)

def check_source(data, profile=CLI):
    if len(data) != profile.size or digest(data) != profile.sha256:
        raise Refused("Unsupported SHA-256. This build has not been reviewed.")
    if data[:8] != bytes.fromhex("cffaedfe0c000001"):
        raise Refused("Expected a macOS ARM64 Mach-O.")
    for edit in profile.edits:
        n = len(edit.before)
        if n != len(edit.after) or edit.offset % 4:
            raise Refused("Invalid patch definition.")
        if data[edit.offset:edit.offset + n] != edit.before:
            raise Refused("Instruction mismatch: " + edit.function)
        if data[edit.offset - 16:edit.offset + n + 16] != edit.context:
            raise Refused("Context mismatch: " + edit.function)

def patch_bytes(data, profile=CLI):
    check_source(data, profile)
    changed = bytearray(data)
    for edit in profile.edits:
        changed[edit.offset:edit.offset + len(edit.before)] = edit.after
    return bytes(changed)

def run_checked(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise Refused("Command failed: " + command[0] + "\n" +
                      (result.stderr or result.stdout).strip())

def verify_signed_copy(raw, signed, profile=CLI):
    if len(signed) < profile.text_end:
        raise Refused("Truncated signed executable.")
    if signed[profile.text_start:profile.text_end] != raw[profile.text_start:profile.text_end]:
        raise Refused("Signing unexpectedly changed executable instructions.")
    for edit in profile.edits:
        if signed[edit.offset:edit.offset + len(edit.after)] != edit.after:
            raise Refused("Output verification failed: " + edit.function)

def check_app(bundle):
    if bundle.is_symlink() or not bundle.is_dir():
        raise Refused("App must be a real directory, not a symlink.")
    # Reject symlink components in the files we will read and change.
    for relative in (APP_BINARY, Path("Contents/Info.plist"), Path("Contents/Resources/app.asar")):
        current = bundle
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise Refused("Unexpected app symlink: " + str(current))
    info_path = bundle / "Contents/Info.plist"
    info_data = info_path.read_bytes()
    info = plistlib.loads(info_data)
    if (info.get("CFBundleIdentifier") != "com.google.antigravity" or
            info.get("CFBundleShortVersionString") != APP.version or
            digest(info_data) != APP_INFO_SHA256):
        raise Refused("Unsupported application identity, version or Info.plist.")
    if file_digest(bundle / "Contents/Resources/app.asar") != APP_ASAR_SHA256:
        raise Refused("Unsupported application resources.")

def tree_inventory(root):
    """Hash files and record symlinks without following framework symlinks."""
    result = {}
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(base) / name
            relative = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                if not path.resolve().is_relative_to(root.resolve()):
                    raise Refused("External bundle symlink: " + relative)
                result[relative] = {"link": os.readlink(path)}
            elif stat.S_ISREG(mode):
                result[relative] = {"sha256": file_digest(path),
                                    "mode": stat.S_IMODE(mode)}
            elif not stat.S_ISDIR(mode):
                raise Refused("Unsupported special file: " + relative)
    return result

def report(source, data, profile=CLI):
    return {
        "source": str(source), "target": profile.target, "version": profile.version,
        "source_sha256": digest(data), "source_size": len(data),
        "platform": "macOS ARM64", "status": "supported",
        "changes": [{"offset": hex(e.offset), "before": e.before.hex(),
                     "after": e.after.hex(), "function": e.function}
                    for e in profile.edits],
        "scope": "Local eligibility handling; server access is not guaranteed.",
    }

def output_location(directory, source):
    directory = directory.expanduser().absolute()
    if directory.exists() or directory.is_symlink():
        raise Refused("Output directory already exists; choose a new directory.")
    directory = directory.parent.resolve(strict=True) / directory.name
    if directory.is_relative_to(source.resolve()):
        raise Refused("Output cannot be inside the source.")
    return directory

def sign_binary(path):
    run_checked(["/usr/bin/codesign", "--force", "--sign", "-", str(path)])
    run_checked(["/usr/bin/codesign", "--verify", "--strict", str(path)])


LIBRARY_VALIDATION_EXCEPTION = "com.apple.security.cs.disable-library-validation"

def macho_metadata(path):
    """Read thin Mach-O dependencies and XML entitlements without running it."""
    import struct
    data = path.read_bytes()
    if data[:4] != bytes.fromhex("cffaedfe") or len(data) < 32:
        return None
    file_type, count, command_bytes = struct.unpack_from("<III", data, 12)
    limit = 32 + command_bytes
    if limit > len(data):
        raise Refused("Invalid Mach-O load-command bounds: " + str(path))
    offset = 32
    dependencies = []
    entitlements = {}
    for unused in range(count):
        if offset + 8 > limit:
            raise Refused("Truncated Mach-O load command.")
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or offset + size > limit:
            raise Refused("Invalid Mach-O load command.")
        if command in (0xc, 0x80000018, 0x8000001f, 0x80000023):
            name_offset = struct.unpack_from("<I", data, offset + 8)[0]
            if name_offset < 24 or name_offset >= size:
                raise Refused("Invalid dylib name.")
            name = data[offset + name_offset:offset + size].split(b"\0", 1)[0]
            dependencies.append(name.decode("utf-8"))
        if command == 0x1d:
            start, length = struct.unpack_from("<II", data, offset + 8)
            if start + length > len(data) or length < 12:
                raise Refused("Invalid code-signature bounds.")
            magic, total, entries = struct.unpack_from(">III", data, start)
            if magic != 0xfade0cc0 or total > length or 12 + entries * 8 > total:
                raise Refused("Invalid code-signature directory.")
            for index in range(entries):
                slot, relative = struct.unpack_from(">II", data, start + 12 + index * 8)
                if slot != 5:
                    continue
                if relative + 8 > total:
                    raise Refused("Invalid entitlement offset.")
                blob_magic, blob_size = struct.unpack_from(">II", data, start + relative)
                if blob_magic != 0xfade7171 or blob_size < 8 or relative + blob_size > total:
                    raise Refused("Invalid entitlement blob.")
                entitlements = plistlib.loads(data[start + relative + 8:start + relative + blob_size])
                if not isinstance(entitlements, dict):
                    raise Refused("Invalid entitlement dictionary.")
        offset += size
    return {"executable": file_type == 2, "dependencies": dependencies,
            "entitlements": entitlements}

def sign_app_copy(bundle):
    # First sign nested code and refresh resource seals as before.
    run_checked(["/usr/bin/codesign", "--force", "--deep", "--sign", "-",
                 "--preserve-metadata=entitlements,flags,runtime", str(bundle)])
    targets = []
    for base, dirs, files in os.walk(bundle, followlinks=False):
        for name in files:
            binary = Path(base) / name
            if binary.is_symlink():
                continue
            with binary.open("rb") as stream:
                magic = stream.read(4)
            if magic != bytes.fromhex("cffaedfe"):
                continue
            metadata = macho_metadata(binary)
            if not metadata["executable"]:
                continue
            local_libraries = any(
                not dep.startswith(("/System/Library/", "/usr/lib/"))
                for dep in metadata["dependencies"])
            if local_libraries:
                targets.append((binary, metadata["entitlements"]))
    exceptions = []
    # Sign helpers first, then the outer app so its resource seal stays valid.
    targets.sort(key=lambda item: len(item[0].parts), reverse=True)
    with tempfile.TemporaryDirectory(prefix=".entitlements-", dir=bundle.parent) as temp:
        for index, (binary, original) in enumerate(targets):
            entitlements = dict(original)
            entitlements[LIBRARY_VALIDATION_EXCEPTION] = True
            settings = Path(temp) / (str(index) + ".plist")
            settings.write_bytes(plistlib.dumps(entitlements))
            target = (binary.parent.parent.parent
                      if binary.parent.name == "MacOS" and binary.parent.parent.name == "Contents"
                      else binary)
            run_checked(["/usr/bin/codesign", "--force", "--sign", "-",
                         "--entitlements", str(settings), "--generate-entitlement-der",
                         "--preserve-metadata=identifier,flags,runtime", str(target)])
            actual = macho_metadata(binary)["entitlements"]
            if actual != entitlements:
                raise Refused("Entitlements were not preserved: " + str(binary))
            exceptions.append(binary.relative_to(bundle).as_posix())
    if "Contents/MacOS/Antigravity" not in exceptions:
        raise Refused("Main executable was not signed for local framework loading.")
    # Changed embedded executables can invalidate framework resource seals too.
    # Re-seal inside out, preserving the explicitly merged entitlements.
    run_checked(["/usr/bin/codesign", "--force", "--deep", "--sign", "-",
                 "--preserve-metadata=entitlements,flags,runtime", str(bundle)])
    for binary, original in targets:
        expected = dict(original)
        expected[LIBRARY_VALIDATION_EXCEPTION] = True
        if macho_metadata(binary)["entitlements"] != expected:
            raise Refused("Final signing changed runtime entitlements.")
    run_checked(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(bundle)])
    return sorted(exceptions)

def electron_loader_smoke(bundle):
    # RunAsNode is enabled in this reviewed Electron build. This executes no
    # application JavaScript, reads no app profile and performs no login.
    framework = bundle / "Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"
    with framework.open("rb") as stream:
        content = stream.read()
    sentinel = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
    position = content.find(sentinel)
    if position < 0 or content[position + len(sentinel):position + len(sentinel) + 3] != b"\x01\x091":
        raise Refused("RunAsNode fuse is not enabled; refusing an unexpected GUI launch.")
    environment = dict(os.environ)
    environment["ELECTRON_RUN_AS_NODE"] = "1"
    result = subprocess.run(
        [str(bundle / "Contents/MacOS/Antigravity"), "-e",
         "process.stdout.write('electron-loader-ok:' + process.versions.electron)"],
        env=environment, capture_output=True, text=True, timeout=30)
    if result.returncode or not result.stdout.startswith("electron-loader-ok:"):
        raise Refused("Electron loader smoke test failed:\n" +
                      (result.stderr or result.stdout).strip())
    return result.stdout.strip()

def build(source, data, directory, profile=CLI):
    if sys.platform != "darwin":
        raise Refused("Signing requires macOS.")
    directory = output_location(directory, source)
    raw = patch_bytes(data, profile)
    if profile.target == "app":
        check_app(source)
        before_tree = tree_inventory(source)
        binary_record = before_tree.get(APP_BINARY.as_posix(), {})
        if binary_record.get("sha256") != profile.sha256:
            raise Refused("Application changed before copying.")
    with tempfile.TemporaryDirectory(prefix=".agy-build-", dir=directory.parent) as scratch:
        staging = Path(scratch) / "result"
        staging.mkdir(mode=0o700)
        manifest = report(source, data, profile)
        if profile.target == "cli":
            executable = staging / "agy"
            executable.write_bytes(raw)
            executable.chmod(0o700)
            sign_binary(executable)
            backup_name = "agy.original"
            artifact_name = "agy"
        else:
            app_copy = staging / "Antigravity.app"
            shutil.copytree(source, app_copy, symlinks=True)
            if tree_inventory(app_copy) != before_tree or tree_inventory(source) != before_tree:
                raise Refused("Source changed during copying, or copy differs.")
            executable = app_copy / APP_BINARY
            executable.write_bytes(raw)
            sign_binary(executable)
            manifest["library_validation_exceptions"] = sign_app_copy(app_copy)
            manifest["electron_loader_smoke"] = electron_loader_smoke(app_copy)
            backup_name = "language_server.original"
            artifact_name = "Antigravity.app"
            after_tree = tree_inventory(app_copy)
            manifest["bundle_source_inventory"] = before_tree
            manifest["bundle_changed_paths"] = [
                name for name in sorted(set(before_tree) | set(after_tree))
                if before_tree.get(name) != after_tree.get(name)]
            manifest["bundle_output_inventory"] = after_tree
            if tree_inventory(source) != before_tree:
                raise Refused("Original application changed during build.")
        signed = executable.read_bytes()
        verify_signed_copy(raw, signed, profile)
        backup = staging / backup_name
        backup.write_bytes(data)
        backup.chmod(0o600)
        if file_digest(backup) != profile.sha256:
            raise Refused("Backup verification failed.")
        if profile.target == "cli" and file_digest(source) != profile.sha256:
            raise Refused("Original CLI changed during build.")
        manifest.update({"patched_sha256": digest(signed),
                         "raw_patched_sha256": digest(raw),
                         "signature": "ad-hoc", "backup": backup_name,
                         "artifact": artifact_name})
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        directory.mkdir(mode=0o700)
        # Publish into our newly created private directory, never over user files.
        for child in staging.iterdir():
            os.rename(child, directory / child.name)
    return directory

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inspect", "patch"))
    parser.add_argument("--target", choices=("cli", "app"), default="cli")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output-dir", type=Path, help="A new output directory")
    args = parser.parse_args(argv)
    try:
        profile = PROFILES[args.target]
        source = args.source or (Path("/Applications/Antigravity.app")
                                 if args.target == "app" else Path.home() / ".local/bin/agy")
        source = source.expanduser().absolute()
        if args.target == "app":
            check_app(source)
        binary = source / APP_BINARY if args.target == "app" else source
        data = read_source(binary, profile)
        check_source(data, profile)
        if args.command == "inspect":
            print(json.dumps(report(source, data, profile), indent=2))
        else:
            if args.output_dir is None:
                raise Refused("patch requires --output-dir pointing to a new directory.")
            directory = build(source, data, args.output_dir, profile)
            print("Created: " + str(directory))
            print("Original installation was not changed. See manifest.json.")
        return 0
    except (Refused, OSError, ValueError, plistlib.InvalidFileException,
            subprocess.SubprocessError) as error:
        print("Refused: " + str(error), file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
