import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

class PrepareApkSigning {
    public static void main(String[] args) throws Exception {
        var keystore = Path.of("TMessagesProj", "release.keystore");
        var localProperties = Path.of("local.properties");
        var encoded = System.getenv("LOCAL_PROPERTIES");
        var properties = new Properties();

        if (encoded != null && !encoded.isBlank()) {
            properties.load(new ByteArrayInputStream(Base64.getDecoder().decode(encoded)));
        } else if (Files.isRegularFile(localProperties)) {
            try (var input = Files.newInputStream(localProperties)) {
                properties.load(input);
            }
        }

        var signingKeys = List.of("KEYSTORE_PASS", "ALIAS_NAME", "ALIAS_PASS");
        if (Files.isRegularFile(keystore) && signingKeys.stream().allMatch(key ->
                !properties.getProperty(key, "").isBlank()
                || !System.getenv().getOrDefault(key, "").isBlank())) {
            if (encoded != null) {
                System.out.print(encoded);
            }
            return;
        }

        var password = UUID.randomUUID().toString();
        var alias = "ci";
        var tempDir = Files.createTempDirectory(keystore.getParent(), ".ci-signing-");
        var tempKeystore = tempDir.resolve("release.keystore");
        try {
            var keytool = Path.of(System.getProperty("java.home"), "bin", "keytool");
            var process = new ProcessBuilder(keytool.toString(),
                    "-genkeypair", "-noprompt", "-storetype", "PKCS12",
                    "-keystore", tempKeystore.toString(), "-storepass:env", "CI_KEYSTORE_PASSWORD",
                    "-alias", alias, "-keyalg", "RSA", "-keysize", "2048",
                    "-validity", "3650", "-dname", "CN=NagramXF CI");
            process.environment().put("CI_KEYSTORE_PASSWORD", password);
            process.redirectErrorStream(true);
            process.redirectOutput(ProcessBuilder.Redirect.PIPE);
            var keytoolProcess = process.start();
            try (var output = keytoolProcess.getInputStream()) {
                output.transferTo(System.err);
            }
            if (keytoolProcess.waitFor() != 0) {
                throw new IllegalStateException("Could not generate the temporary APK signing key");
            }
            Files.move(tempKeystore, keystore, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(tempKeystore);
            Files.deleteIfExists(tempDir);
        }

        properties.setProperty("KEYSTORE_PASS", password);
        properties.setProperty("ALIAS_NAME", alias);
        properties.setProperty("ALIAS_PASS", password);
        var output = new ByteArrayOutputStream();
        properties.store(output, null);
        System.out.print(Base64.getEncoder().encodeToString(output.toByteArray()));
    }
}
