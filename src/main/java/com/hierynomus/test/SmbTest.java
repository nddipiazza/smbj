package com.hierynomus.test;

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import java.util.concurrent.TimeUnit;

import static com.hierynomus.msdtyp.AccessMask.GENERIC_READ;
import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_OPEN;
import static com.hierynomus.mssmb2.SMB2ShareAccess.FILE_SHARE_READ;
import static java.util.EnumSet.of;

public class SmbTest {

    @Option(name = "-serverName", required = true, usage = "server name")
    private String serverName;
    @Option(name = "-port", usage = "port")
    private int port = 445;
    @Option(name = "-path", required = true, usage = "path")
    private String path;
    @Option(name = "-share", required = true, usage = "share")
    private String share;
    @Option(name = "-domain", required = true, usage = "domain")
    private String domain;
    @Option(name = "-username", required = true, usage = "username")
    private String username;
    @Option(name = "-password", usage = "password")
    private String password;
    @Option(name = "-enableDfs", usage = "enable dfs")
    private boolean enableDfs;
    @Option(name = "-timeout", usage = "timeout")
    private int timeout = 120;
    @Option(name = "-socketTimeout", usage = "socket timeout")
    private int socketTimeout = 120;

    public static void main(String [] args) throws Exception {
        SmbTest smbTest = new SmbTest();

        CmdLineParser parser = new CmdLineParser(smbTest);

        try {
            parser.parseArgument(args);
        } catch (Exception e) {
            parser.printUsage(System.out);
            e.printStackTrace();
            System.exit(1);
        }

        smbTest.runTest();
    }

    private void runTest() throws Exception {
        if (password == null || password.trim().equals("")) {
            password = new String(System.console().readPassword("Enter Password: "));
            if ("".equals(password.trim())) {
                System.exit(1);
            }
        }

        SmbConfig smbConfig = SmbConfig.builder().withDfsEnabled(enableDfs)
                .withMultiProtocolNegotiate(true)
                .withTimeout(timeout, TimeUnit.SECONDS)
                .withSoTimeout(socketTimeout, TimeUnit.SECONDS)
                .build();

        AuthenticationContext authenticationContext = new AuthenticationContext(username, password.toCharArray(), domain);

        SMBClient smbClient = new SMBClient(smbConfig);

        try (Connection connection = smbClient.connect(serverName, port)) {
            Session session = connection.authenticate(authenticationContext);
            DiskShare diskShare = (DiskShare)session.connectShare(share);
            Directory result = diskShare.openDirectory(path, of(GENERIC_READ), null, of(FILE_SHARE_READ), FILE_OPEN, null);
            System.out.println("Result: " + result);
            System.out.println("Filename: " + result.getFileName());
            System.out.println("File ID: " + result.getFileId());
        }
    }
}
