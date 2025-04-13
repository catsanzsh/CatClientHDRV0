import os
import sys
import subprocess
import platform
import urllib.request
import zipfile
import json
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import hashlib

# Define constants for directories and URLs
MINECRAFT_DIR = os.path.expanduser("~/.minecraft")
VERSIONS_DIR = os.path.join(MINECRAFT_DIR, "versions")
JAVA_DIR = os.path.expanduser("~/.catclient/java")
VERSION_MANIFEST_URL = "https://launchermeta.mojang.com/mc/game/version_manifest.json"

class CatClientv0HDR(tk.Tk):
    def __init__(self):
        """Initialize the launcher window and UI."""
        super().__init__()
        self.title("CatClientv0HDR")
        self.geometry("600x400")
        self.resizable(False, False)
        self.configure(bg="#202020")
        self.versions = {}  # Dictionary to store version IDs and their URLs
        self.init_ui()

    def init_ui(self):
        """Set up the graphical user interface."""
        sidebar = tk.Frame(self, bg="#2a2a2a", width=200)
        sidebar.pack(side="left", fill="y")

        logo = tk.Label(sidebar, text="😺 CatClientv0HDR", font=("Arial", 14), bg="#2a2a2a", fg="white")
        logo.pack(pady=10)

        self.username_input = tk.Entry(sidebar, font=("Arial", 10), bg="#333333", fg="white", insertbackground="white")
        self.username_input.insert(0, "Enter Username")
        self.username_input.bind("<FocusIn>", lambda e: self.username_input.delete(0, tk.END) if self.username_input.get() == "Enter Username" else None)
        self.username_input.pack(pady=5, padx=10, fill="x")

        self.version_combo = ttk.Combobox(sidebar, font=("Arial", 10), state="readonly")
        self.load_version_manifest()
        self.version_combo.pack(pady=5, padx=10, fill="x")

        tk.Label(sidebar, text="RAM (GB)", font=("Arial", 10), bg="#2a2a2a", fg="white").pack(pady=5)
        self.ram_scale = tk.Scale(sidebar, from_=1, to=16, orient="horizontal", bg="#2a2a2a", fg="white", highlightthickness=0)
        self.ram_scale.set(4)
        self.ram_scale.pack(pady=5, padx=10, fill="x")

        skin_button = tk.Button(sidebar, text="Apply Skin", font=("Arial", 10), bg="#333333", fg="white", command=self.select_skin)
        skin_button.pack(pady=5, padx=10, fill="x")

        launch_button = tk.Button(sidebar, text="Launch Minecraft", font=("Arial", 12), bg="#4CAF50", fg="white", command=self.download_and_launch)
        launch_button.pack(pady=20, padx=10, fill="x")

        main_area = tk.Label(self, text="Welcome to CatClientv0HDR!\nA Custom Minecraft Launcher 🐾", font=("Arial", 14), bg="#202020", fg="white")
        main_area.pack(expand=True)

    def load_version_manifest(self):
        """Load the list of available Minecraft versions from Mojang's servers."""
        try:
            with urllib.request.urlopen(VERSION_MANIFEST_URL) as url:
                manifest = json.loads(url.read().decode())
                for v in manifest["versions"]:
                    self.versions[v["id"]] = v["url"]
                self.version_combo["values"] = list(self.versions.keys())
                if self.versions:
                    self.version_combo.current(0)
        except Exception as e:
            print(f"Error loading version manifest: {e}")
            messagebox.showerror("Error", "Failed to load version manifest. Check your internet connection.")

    def is_java_installed(self, required_version="21"):
        """Check if a compatible Java version (21 or higher) is installed."""
        try:
            result = subprocess.run(["java", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stderr
            match = re.search(r'version "(\d+)', output)
            if match:
                major_version = int(match.group(1))
                return major_version >= int(required_version)
            return False
        except Exception:
            return False

    def install_java_if_needed(self):
        """Install OpenJDK 21 if a compatible Java version is not found."""
        if self.is_java_installed():
            return
        print("Installing OpenJDK 21...")
        system = platform.system()
        if system == "Windows":
            java_url = "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.5%2B11/OpenJDK21U-jdk_x64_windows_hotspot_21.0.5_11.zip"
        elif system == "Linux":
            java_url = "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.5%2B11/OpenJDK21U-jdk_x64_linux_hotspot_21.0.5_11.tar.gz"
        elif system == "Darwin":
            java_url = "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.5%2B11/OpenJDK21U-jdk_x64_mac_hotspot_21.0.5_11.tar.gz"
        else:
            messagebox.showerror("Error", "Unsupported OS")
            return

        archive_path = os.path.join(JAVA_DIR, "openjdk.zip" if system == "Windows" else "openjdk.tar.gz")
        os.makedirs(JAVA_DIR, exist_ok=True)

        try:
            urllib.request.urlretrieve(java_url, archive_path)
        except Exception as e:
            print(f"Failed to download Java: {e}")
            messagebox.showerror("Error", "Failed to download Java 21. Please check your internet connection or install Java manually.")
            return

        if system == "Windows":
            with zipfile.ZipFile(archive_path, "r") as zip_ref:
                zip_ref.extractall(JAVA_DIR)
        else:
            import tarfile
            with tarfile.open(archive_path, "r:gz") as tar_ref:
                tar_ref.extractall(JAVA_DIR)
            # Set execute permissions for Java binary on Linux and macOS
            java_bin = os.path.join(JAVA_DIR, "jdk-21.0.5+11", "bin", "java")
            os.chmod(java_bin, 0o755)  # Make Java executable
        os.remove(archive_path)
        print("Java 21 installed locally.")

    def select_skin(self):
        """Allow the user to select and apply a custom skin PNG file."""
        file_path = filedialog.askopenfilename(filetypes=[("PNG Files", "*.png")])
        if file_path:
            skin_dest = os.path.join(MINECRAFT_DIR, "skins")
            os.makedirs(skin_dest, exist_ok=True)
            shutil.copy(file_path, os.path.join(skin_dest, "custom_skin.png"))
            messagebox.showinfo("Skin Applied", "Skin applied successfully! Note: This may require a mod to apply in-game.")

    @staticmethod
    def verify_file(file_path, expected_sha1):
        """Verify the SHA1 checksum of a file."""
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha1(f.read()).hexdigest()
        return file_hash == expected_sha1

    def download_version_files(self, version_id, version_url):
        """Download the version JSON, JAR, libraries, and natives with checksum verification."""
        print(f"⬇️ Downloading version files for {version_id}...")
        version_dir = os.path.join(VERSIONS_DIR, version_id)
        os.makedirs(version_dir, exist_ok=True)

        # Download version JSON
        version_json_path = os.path.join(version_dir, f"{version_id}.json")
        try:
            with urllib.request.urlopen(version_url) as url:
                data = json.loads(url.read().decode())
                with open(version_json_path, "w") as f:
                    json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Failed to download version JSON: {e}")
            messagebox.showerror("Error", f"Failed to download version {version_id} JSON.")
            return

        # Download and verify client JAR
        try:
            jar_url = data["downloads"]["client"]["url"]
            jar_path = os.path.join(version_dir, f"{version_id}.jar")
            expected_sha1 = data["downloads"]["client"]["sha1"]
            if not os.path.exists(jar_path) or not CatClientv0HDR.verify_file(jar_path, expected_sha1):
                urllib.request.urlretrieve(jar_url, jar_path)
                if not CatClientv0HDR.verify_file(jar_path, expected_sha1):
                    print(f"Checksum mismatch for {jar_path}")
                    messagebox.showerror("Error", f"Checksum mismatch for version {version_id} JAR.")
                    return
        except KeyError as e:
            print(f"Missing client JAR info in JSON: {e}")
            messagebox.showerror("Error", f"Version {version_id} is missing client JAR information.")
            return

        current_os = platform.system().lower()
        if current_os == "darwin":
            current_os = "osx"

        libraries_dir = os.path.join(MINECRAFT_DIR, "libraries")
        os.makedirs(libraries_dir, exist_ok=True)
        natives_dir = os.path.join(version_dir, "natives")
        os.makedirs(natives_dir, exist_ok=True)

        # Download libraries and natives
        for lib in data.get("libraries", []):
            if self.is_library_allowed(lib, current_os):
                # Download library artifact
                if "downloads" in lib and "artifact" in lib["downloads"]:
                    lib_url = lib["downloads"]["artifact"]["url"]
                    lib_path = os.path.join(libraries_dir, lib["downloads"]["artifact"]["path"])
                    os.makedirs(os.path.dirname(lib_path), exist_ok=True)
                    expected_sha1 = lib["downloads"]["artifact"]["sha1"]
                    if not os.path.exists(lib_path) or not CatClientv0HDR.verify_file(lib_path, expected_sha1):
                        try:
                            urllib.request.urlretrieve(lib_url, lib_path)
                            if not CatClientv0HDR.verify_file(lib_path, expected_sha1):
                                print(f"Checksum mismatch for {lib_path}")
                                messagebox.showerror("Error", f"Checksum mismatch for library {lib.get('name', 'unknown')}.")
                                return
                        except Exception as e:
                            print(f"Failed to download library {lib.get('name', 'unknown')}: {e}")

                # Download and extract natives
                if "natives" in lib and current_os in lib["natives"]:
                    classifier = lib["natives"][current_os]
                    if "downloads" in lib and "classifiers" in lib["downloads"] and classifier in lib["downloads"]["classifiers"]:
                        native_url = lib["downloads"]["classifiers"][classifier]["url"]
                        native_path = os.path.join(natives_dir, f"{classifier}.jar")
                        expected_sha1 = lib["downloads"]["classifiers"][classifier]["sha1"]
                        if not os.path.exists(native_path) or not CatClientv0HDR.verify_file(native_path, expected_sha1):
                            try:
                                urllib.request.urlretrieve(native_url, native_path)
                                if not CatClientv0HDR.verify_file(native_path, expected_sha1):
                                    print(f"Checksum mismatch for {native_path}")
                                    messagebox.showerror("Error", f"Checksum mismatch for native {lib.get('name', 'unknown')}.")
                                    return
                            except Exception as e:
                                print(f"Failed to download native {lib.get('name', 'unknown')}: {e}")
                                return
                        try:
                            with zipfile.ZipFile(native_path, "r") as zip_ref:
                                zip_ref.extractall(natives_dir)
                            os.remove(native_path)
                        except Exception as e:
                            print(f"Failed to extract native {lib.get('name', 'unknown')}: {e}")

        print("✅ Download complete!")

    def is_library_allowed(self, lib, current_os):
        """Check if a library is allowed on the current OS based on its rules."""
        if "rules" not in lib:
            return True
        allowed = False
        for rule in lib["rules"]:
            if rule["action"] == "allow":
                if "os" not in rule or (isinstance(rule.get("os"), dict) and rule["os"].get("name") == current_os):
                    allowed = True
            elif rule["action"] == "disallow":
                if "os" in rule and isinstance(rule.get("os"), dict) and rule["os"].get("name") == current_os:
                    allowed = False
        return allowed

    def evaluate_rules(self, rules, current_os):
        """Evaluate argument rules based on the current OS, ignoring feature-based rules."""
        if not rules:
            return True
        allowed = False
        for rule in rules:
            if "features" in rule:
                continue  # Skip feature-based rules
            if rule["action"] == "allow":
                if "os" not in rule or (isinstance(rule.get("os"), dict) and rule["os"].get("name") == current_os):
                    allowed = True
            elif rule["action"] == "disallow":
                if "os" in rule and isinstance(rule.get("os"), dict) and rule["os"].get("name") == current_os:
                    allowed = False
        return allowed

    def generate_offline_uuid(self, username):
        """Generate a UUID for offline mode based on the username."""
        offline_prefix = "OfflinePlayer:"
        hash_value = hashlib.md5((offline_prefix + username).encode('utf-8')).hexdigest()
        uuid_str = f"{hash_value[:8]}-{hash_value[8:12]}-{hash_value[12:16]}-{hash_value[16:20]}-{hash_value[20:32]}"
        return uuid_str

    def build_launch_command(self, version, username, ram):
        """Construct the command to launch Minecraft."""
        version_dir = os.path.join(VERSIONS_DIR, version)
        json_path = os.path.join(version_dir, f"{version}.json")

        try:
            with open(json_path, "r") as f:
                version_data = json.load(f)
        except Exception as e:
            print(f"Failed to read version JSON: {e}")
            messagebox.showerror("Error", f"Cannot read version {version} JSON.")
            return []

        current_os = platform.system().lower()
        if current_os == "darwin":
            current_os = "osx"

        main_class = version_data.get("mainClass", "net.minecraft.client.main.Main")
        libraries_dir = os.path.join(MINECRAFT_DIR, "libraries")
        natives_dir = os.path.join(version_dir, "natives")
        jar_path = os.path.join(version_dir, f"{version}.jar")
        classpath = [jar_path]

        for lib in version_data.get("libraries", []):
            if "downloads" in lib and "artifact" in lib["downloads"]:
                lib_path = os.path.join(libraries_dir, lib["downloads"]["artifact"]["path"])
                if os.path.exists(lib_path):
                    classpath.append(lib_path)

        classpath_str = ";".join(classpath) if platform.system() == "Windows" else ":".join(classpath)
        java_path = "java" if self.is_java_installed() else os.path.join(JAVA_DIR, "jdk-21.0.5+11", "bin", "java.exe" if platform.system() == "Windows" else "java")

        command = [java_path, f"-Xmx{ram}G"]

        # JVM arguments
        jvm_args = []
        if "arguments" in version_data and "jvm" in version_data["arguments"]:
            for arg in version_data["arguments"]["jvm"]:
                if isinstance(arg, str):
                    jvm_args.append(arg)
                elif isinstance(arg, dict) and "rules" in arg and "value" in arg:
                    if self.evaluate_rules(arg["rules"], current_os):
                        if isinstance(arg["value"], list):
                            jvm_args.extend(arg["value"])
                        else:
                            jvm_args.append(arg["value"])

        if platform.system() == "Darwin" and "-XstartOnFirstThread" not in jvm_args:
            jvm_args.append("-XstartOnFirstThread")

        if not any("-Djava.library.path" in arg for arg in jvm_args):
            jvm_args.append(f"-Djava.library.path={natives_dir}")

        command.extend(jvm_args)

        # Game arguments
        game_args = []
        if "arguments" in version_data and "game" in version_data["arguments"]:
            for arg in version_data["arguments"]["game"]:
                if isinstance(arg, str):
                    game_args.append(arg)
                elif isinstance(arg, dict) and "rules" in arg and "value" in arg:
                    if self.evaluate_rules(arg["rules"], current_os):
                        if isinstance(arg["value"], list):
                            game_args.extend(arg["value"])
                        else:
                            game_args.append(arg["value"])
        elif "minecraftArguments" in version_data:
            game_args = version_data["minecraftArguments"].split()

        # Offline UUID
        uuid = self.generate_offline_uuid(username)

        # Placeholder replacements
        replacements = {
            "${auth_player_name}": username,
            "${version_name}": version,
            "${game_directory}": MINECRAFT_DIR,
            "${assets_root}": os.path.join(MINECRAFT_DIR, "assets"),
            "${assets_index_name}": version_data.get("assetIndex", {}).get("id", "legacy"),
            "${auth_uuid}": uuid,
            "${auth_access_token}": "0",
            "${user_type}": "legacy",
            "${version_type}": version_data.get("type", "release"),
            "${user_properties}": "{}",
            "${quickPlayRealms}": "",
        }

        def replace_placeholders(arg):
            for key, value in replacements.items():
                arg = arg.replace(key, value)
            return arg

        game_args = [replace_placeholders(arg) for arg in game_args]
        jvm_args = [replace_placeholders(arg) for arg in jvm_args]

        command.extend(["-cp", classpath_str, main_class] + game_args)
        return command

    def download_and_launch(self):
        """Handle the download and launch process."""
        self.install_java_if_needed()
        version = self.version_combo.get()
        if not version:
            messagebox.showerror("Error", "No version selected.")
            return

        username = self.username_input.get() or "Steve"
        ram = int(self.ram_scale.get())
        version_url = self.versions.get(version)

        if not version_url:
            messagebox.showerror("Error", f"Version {version} URL not found.")
            return

        self.download_version_files(version, version_url)

        launch_cmd = self.build_launch_command(version, username, ram)
        if not launch_cmd:
            return

        print("🚀 Launching Minecraft with:", " ".join(launch_cmd))
        try:
            subprocess.Popen(launch_cmd)
        except Exception as e:
            print(f"Failed to launch Minecraft: {e}")
            messagebox.showerror("Error", f"Failed to launch Minecraft: {e}")

if __name__ == "__main__":
    app = CatClientv0HDR()
    app.mainloop()
