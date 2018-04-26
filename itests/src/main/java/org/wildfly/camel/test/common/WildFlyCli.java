package org.wildfly.camel.test.common;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;

public class WildFlyCli {

    private static class StreamGobbler extends Thread {
        private final InputStream in;
        private final StringBuilder buffer = new StringBuilder();
        private IOException exception;

        private StreamGobbler(InputStream in) {
            this.in = in;
        }

        @Override
        public void run() {
            try (InputStreamReader r = new InputStreamReader(in, StandardCharsets.UTF_8)) {
                int ch;
                while ((ch = r.read()) >= 0) {
                    buffer.append((char) ch);
                }
            } catch (IOException e) {
                exception = e;
            }
        }

        public String getString() throws IOException {
            if (exception != null) {
                throw exception;
            } else {
                return buffer.toString();
            }
        }
    }
    public static class WildFlyCliResult {
        private final int exitValue;
        private final String stdErr;
        private final String stdOut;
        private final String[] command;
        WildFlyCliResult(String[] command, int exitValue, String stdOut, String stdErr) {
            super();
            this.command = command;
            this.exitValue = exitValue;
            this.stdOut = stdOut;
            this.stdErr = stdErr;
        }
        public int getExitValue() {
            return exitValue;
        }
        public String getStdErr() {
            return stdErr;
        }
        public String getStdOut() {
            return stdOut;
        }

        public WildFlyCliResult assertSuccess() {
            if (exitValue != 0) {
                throw new RuntimeException(String.format("Command %s returned %d.\n\nstdout: %s\n\nstdErr: %s", Arrays.toString(command), exitValue, stdOut, stdErr));
            }
            if (!stdErr.isEmpty()) {
                throw new RuntimeException(String.format("Command %s exited with non empty stdErr: %s", Arrays.toString(command), stdErr));
            }
            return this;
        }
    }

    private final Path wildFlyHome;

    public WildFlyCli(Path wildFlyHome) {
        super();
        this.wildFlyHome = wildFlyHome;
    }

    public WildFlyCliResult run(Path cliScript) throws IOException, InterruptedException {
        final ProcessBuilder pb = new ProcessBuilder();
        final String[] command;
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            final String jbossCliPath = wildFlyHome.resolve("bin/jboss-cli.bat").normalize().toString();
            command = new String[] {"cmd.exe", jbossCliPath, "--connect", "--file=" + cliScript.normalize().toString()};
        } else {
            final String jbossCliPath = wildFlyHome.resolve("bin/jboss-cli.sh").normalize().toString();
            command = new String[] {"/bin/sh", jbossCliPath, "--connect", "--file=" + cliScript.normalize().toString()};
        }
        pb.command(command);
        Process process = pb.start();
        StreamGobbler stdOut = new StreamGobbler(process.getInputStream());
        StreamGobbler stdErr = new StreamGobbler(process.getErrorStream());
        int exitCode = process.waitFor();

        return new WildFlyCliResult(command, exitCode, stdOut.getString(), stdErr.getString());
    }

}
