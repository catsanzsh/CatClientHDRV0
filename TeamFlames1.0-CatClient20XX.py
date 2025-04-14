import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class LaunchManager {
    private String currentOs;

    public LaunchManager() {
        String osName = System.getProperty("os.name").toLowerCase();
        if (osName.contains("win")) {
            currentOs = "windows";
        } else if (osName.contains("mac")) {
            currentOs = "osx";
        } else if (osName.contains("linux")) {
            currentOs = "linux";
        } else {
            throw new RuntimeException("Unsupported OS: " + osName);
        }
        System.out.println("Detected OS: " + currentOs);
    }

    public void downloadVersionFiles(String version, String versionUrl) throws IOException {
        Path versionDir = Paths.get(System.getProperty("user.home"), ".minecraft", "versions", version);
        Files.createDirectories(versionDir);
        Path jsonPath = versionDir.resolve(version + ".json");
        System.out.println("Downloading version JSON from " + versionUrl + " to " + jsonPath);
        DownloadManager.downloadFile(versionUrl, jsonPath, null);

        JsonObject versionData;
        try (Reader reader = Files.newBufferedReader(jsonPath)) {
            versionData = new JsonParser().parse(reader).getAsJsonObject();
        }

        // Download client JAR
        if (versionData.has("downloads") && versionData.getAsJsonObject("downloads").has("client")) {
            JsonObject client = versionData.getAsJsonObject("downloads").getAsJsonObject("client");
            String jarUrl = client.get("url").getAsString();
            String jarSha1 = client.get("sha1").getAsString();
            Path jarPath = versionDir.resolve(version + ".jar");
            System.out.println("Downloading client JAR from " + jarUrl + " to " + jarPath);
            DownloadManager.downloadFile(jarUrl, jarPath, jarSha1);
        } else {
            throw new IOException("Client download information missing in version JSON");
        }

        // Download libraries and natives
        Path librariesDir = Paths.get(System.getProperty("user.home"), ".minecraft", "libraries");
        Path nativesDir = versionDir.resolve("natives");
        Files.createDirectories(librariesDir);
        Files.createDirectories(nativesDir);

        if (versionData.has("libraries")) {
            JsonArray libraries = versionData.getAsJsonArray("libraries");
            for (JsonElement libElem : libraries) {
                JsonObject lib = libElem.getAsJsonObject();
                if (isLibraryAllowed(lib)) {
                    if (lib.has("downloads") && lib.getAsJsonObject("downloads").has("artifact")) {
                        JsonObject artifact = lib.getAsJsonObject("downloads").getAsJsonObject("artifact");
                        String libUrl = artifact.get("url").getAsString();
                        String libPathStr = artifact.get("path").getAsString();
                        Path libPath = librariesDir.resolve(libPathStr);
                        Files.createDirectories(libPath.getParent());
                        String libSha1 = artifact.get("sha1").getAsString();
                        System.out.println("Downloading library from " + libUrl + " to " + libPath);
                        DownloadManager.downloadFile(libUrl, libPath, libSha1);
                    }
                    if (lib.has("natives") && lib.getAsJsonObject("natives").has(currentOs)) {
                        String classifier = lib.getAsJsonObject("natives").get(currentOs).getAsString();
                        JsonObject downloads = lib.getAsJsonObject("downloads");
                        if (downloads != null && downloads.has("classifiers")) {
                            JsonObject classifiers = downloads.getAsJsonObject("classifiers");
                            if (classifiers.has(classifier)) {
                                JsonObject nativeArtifact = classifiers.getAsJsonObject(classifier);
                                String nativeUrl = nativeArtifact.get("url").getAsString();
                                String nativeSha1 = nativeArtifact.get("sha1").getAsString();
                                Path nativeJarPath = nativesDir.resolve(classifier + ".jar");
                                System.out.println("Downloading native JAR from " + nativeUrl + " to " + nativeJarPath);
                                DownloadManager.downloadFile(nativeUrl, nativeJarPath, nativeSha1);
                                System.out.println("Extracting natives to " + nativesDir);
                                try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(nativeJarPath))) {
                                    ZipEntry entry;
                                    while ((entry = zis.getNextEntry()) != null) {
                                        if (!entry.isDirectory()) {
                                            Path entryPath = nativesDir.resolve(entry.getName());
                                            System.out.println("Extracting " + entry.getName() + " to " + entryPath);
                                            Files.copy(zis, entryPath, StandardCopyOption.REPLACE_EXISTING);
                                        }
                                    }
                                }
                                Files.delete(nativeJarPath);
                            }
                        }
                    }
                }
            }
        }
    }

    public void modifyOptionsTxt() throws IOException {
        Path optionsPath = Paths.get(System.getProperty("user.home"), ".minecraft", "options.txt");
        Map<String, String> options = new HashMap<>();
        if (Files.exists(optionsPath)) {
            List<String> lines = Files.readAllLines(optionsPath);
            for (String line : lines) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    options.put(parts[0], parts[1]);
                }
            }
        }
        options.put("maxFps", "60");
        options.put("enableVsync", "false");
        List<String> lines = new ArrayList<>();
        for (Map.Entry<String, String> entry : options.entrySet()) {
            lines.add(entry.getKey() + ":" + entry.getValue());
        }
        System.out.println("Writing options.txt to " + optionsPath);
        Files.write(optionsPath, lines);
    }

    public List<String> buildLaunchCommand(String version, String username, int ram) throws IOException {
        Path versionDir = Paths.get(System.getProperty("user.home"), ".minecraft", "versions", version);
        Path jsonPath = versionDir.resolve(version + ".json");
        JsonObject versionData;
        try (Reader reader = Files.newBufferedReader(jsonPath)) {
            versionData = new JsonParser().parse(reader).getAsJsonObject();
        }

        if (!versionData.has("mainClass")) {
            throw new IOException("Main class missing in version JSON");
        }
        String mainClass = versionData.get("mainClass").getAsString();
        Path librariesDir = Paths.get(System.getProperty("user.home"), ".minecraft", "libraries");
        Path nativesDir = versionDir.resolve("natives");
        List<String> classpath = new ArrayList<>();
        classpath.add(versionDir.resolve(version + ".jar").toString());
        if (versionData.has("libraries")) {
            for (JsonElement libElem : versionData.getAsJsonArray("libraries")) {
                JsonObject lib = libElem.getAsJsonObject();
                if (isLibraryAllowed(lib) && lib.has("downloads") && lib.getAsJsonObject("downloads").has("artifact")) {
                    String libPathStr = lib.getAsJsonObject("downloads").getAsJsonObject("artifact").get("path").getAsString();
                    Path libPath = librariesDir.resolve(libPathStr);
                    if (Files.exists(libPath)) {
                        classpath.add(libPath.toString());
                    } else {
                        System.out.println("Warning: Library not found: " + libPath);
                    }
                }
            }
        }
        String classpathStr = String.join(System.getProperty("path.separator"), classpath);

        List<String> jvmArgs = new ArrayList<>();
        if (versionData.has("arguments") && versionData.getAsJsonObject("arguments").has("jvm")) {
            JsonArray jvmArgsArray = versionData.getAsJsonObject("arguments").getAsJsonArray("jvm");
            for (JsonElement argElem : jvmArgsArray) {
                if (argElem.isJsonPrimitive()) {
                    jvmArgs.add(argElem.getAsString());
                } else if (argElem.isJsonObject() && evaluateRules(argElem.getAsJsonObject().getAsJsonArray("rules"))) {
                    JsonElement value = argElem.getAsJsonObject().get("value");
                    if (value.isJsonArray()) {
                        for (JsonElement val : value.getAsJsonArray()) {
                            jvmArgs.add(val.getAsString());
                        }
                    } else {
                        jvmArgs.add(value.getAsString());
                    }
                }
            }
        }
        if (!jvmArgs.stream().anyMatch(arg -> arg.contains("-Djava.library.path"))) {
            jvmArgs.add("-Djava.library.path=" + nativesDir.toString());
        }
        if (currentOs.equals("osx") && !jvmArgs.contains("-XstartOnFirstThread")) {
            jvmArgs.add("-XstartOnFirstThread");
        }

        List<String> gameArgs = new ArrayList<>();
        if (versionData.has("arguments") && versionData.getAsJsonObject("arguments").has("game")) {
            JsonArray gameArgsArray = versionData.getAsJsonObject("arguments").getAsJsonArray("game");
            for (JsonElement argElem : gameArgsArray) {
                if (argElem.isJsonPrimitive()) {
                    gameArgs.add(argElem.getAsString());
                } else if (argElem.isJsonObject() && evaluateRules(argElem.getAsJsonObject().getAsJsonArray("rules"))) {
                    JsonElement value = argElem.getAsJsonObject().get("value");
                    if (value.isJsonArray()) {
                        for (JsonElement val : value.getAsJsonArray()) {
                            gameArgs.add(val.getAsString());
                        }
                    } else {
                        gameArgs.add(value.getAsString());
                    }
                }
            }
        } else if (versionData.has("minecraftArguments")) {
            gameArgs.addAll(Arrays.asList(versionData.get("minecraftArguments").getAsString().split(" ")));
        }

        String uuid = generateOfflineUuid(username);
        Map<String, String> replacements = new HashMap<>();
        replacements.put("${auth_player_name}", username);
        replacements.put("${version_name}", version);
        replacements.put("${game_directory}", Paths.get(System.getProperty("user.home"), ".minecraft").toString());
        replacements.put("${assets_root}", Paths.get(System.getProperty("user.home"), ".minecraft", "assets").toString());
        String assetIndex = versionData.has("assetIndex") ? versionData.getAsJsonObject("assetIndex").get("id").getAsString() : "legacy";
        replacements.put("${assets_index_name}", assetIndex);
        replacements.put("${auth_uuid}", uuid);
        replacements.put("${auth_access_token}", "0");
        replacements.put("${user_type}", "legacy");
        replacements.put("${version_type}", versionData.get("type").getAsString());
        replacements.put("${user_properties}", "{}");
        replacements.put("${quickPlayRealms}", "");

        // Process JVM arguments with replacements
        List<String> finalJvmArgs = new ArrayList<>();
        for (String arg : jvmArgs) {
            String processedArg = arg;
            for (Map.Entry<String, String> entry : replacements.entrySet()) {
                processedArg = processedArg.replace(entry.getKey(), entry.getValue());
            }
            finalJvmArgs.add(processedArg);
        }

        // Process Game arguments with replacements
        List<String> finalGameArgs = new ArrayList<>();
        for (String arg : gameArgs) {
            String processedArg = arg;
            for (Map.Entry<String, String> entry : replacements.entrySet()) {
                processedArg = processedArg.replace(entry.getKey(), entry.getValue());
            }
            finalGameArgs.add(processedArg);
        }

        // Build the final command list
        List<String> finalCommand = new ArrayList<>();
        finalCommand.add("java");
        finalCommand.add("-Xmx" + ram + "G");
        finalCommand.addAll(finalJvmArgs);
        finalCommand.add("-cp");
        finalCommand.add(classpathStr);
        finalCommand.add(mainClass);
        finalCommand.addAll(finalGameArgs);

        System.out.println("Launch command: " + String.join(" ", finalCommand));
        return finalCommand;
    }

    private boolean isLibraryAllowed(JsonObject lib) {
        if (!lib.has("rules")) {
            return true;
        }
        boolean allowed = false;
        JsonArray rules = lib.getAsJsonArray("rules");
        for (JsonElement ruleElem : rules) {
            JsonObject rule = ruleElem.getAsJsonObject();
            String action = rule.get("action").getAsString();
            if (action.equals("allow")) {
                if (!rule.has("os") || rule.getAsJsonObject("os").get("name").getAsString().equals(currentOs)) {
                    allowed = true;
                }
            } else if (action.equals("disallow")) {
                if (rule.has("os") && rule.getAsJsonObject("os").get("name").getAsString().equals(currentOs)) {
                    allowed = false;
                }
            }
        }
        return allowed;
    }

    private boolean evaluateRules(JsonArray rules) {
        if (rules == null || rules.size() == 0) {
            return true;
        }
        boolean allowed = false;
        for (JsonElement ruleElem : rules) {
            JsonObject rule = ruleElem.getAsJsonObject();
            if (rule.has("features")) {
                continue;
            }
            String action = rule.get("action").getAsString();
            if (action.equals("allow")) {
                if (!rule.has("os") || rule.getAsJsonObject("os").get("name").getAsString().equals(currentOs)) {
                    allowed = true;
                }
            } else if (action.equals("disallow")) {
                if (rule.has("os") && rule.getAsJsonObject("os").get("name").getAsString().equals(currentOs)) {
                    allowed = false;
                }
            }
        }
        return allowed;
    }

    private String generateOfflineUuid(String username) {
        String offlinePrefix = "OfflinePlayer:";
        String data = offlinePrefix + username;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(data.getBytes("UTF-8"));
            String hashHex = DownloadManager.bytesToHex(hash);
            return hashHex.substring(0, 8) + "-" + hashHex.substring(8, 12) + "-" +
                   hashHex.substring(12, 16) + "-" + hashHex.substring(16, 20) + "-" + hashHex.substring(20, 32);
        } catch (NoSuchAlgorithmException | java.io.UnsupportedEncodingException e) {
            throw new RuntimeException("Failed to generate offline UUID", e);
        }
    }
}
