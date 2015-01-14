package kfs.kfsjettyjdbcloginservice;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.MappedLoginService;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.Loader;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.security.Credential;

/**
 * Hello world!
 *
 */
public final class tomcatLikeJdbcLoginService extends MappedLoginService {

    private static final Logger LOG = Log.getLogger(tomcatLikeJdbcLoginService.class);

    private String jdbcDriver;
    private String url;
    private String userName;
    private String password;

    private String userTable;
    private String userTableLogin;
    private String userTablePassword;
    private String passwordPrefix;
    private String roleTable;
    private String roleTableUser;
    private String roleTableRole;
    private int cacheTime;

    private String config;
    private long lastHashPurge;
    private Connection con;
    private String userSql;
    private String roleSql;

    public tomcatLikeJdbcLoginService() throws IOException {
    }

    public tomcatLikeJdbcLoginService(String name) throws IOException {
        setName(name);
    }

    public tomcatLikeJdbcLoginService(String name, String config) throws IOException {
        setName(name);
        setConfig(config);
    }

    public tomcatLikeJdbcLoginService(String name, IdentityService identityService, String config)
            throws IOException {
        setName(name);
        setIdentityService(identityService);
        setConfig(config);
    }

    /**
     * @throws java.lang.Exception
     * @see org.eclipse.jetty.security.MappedLoginService#doStart()
     */
    @Override
    protected void doStart() throws Exception {
        Properties properties = new Properties();
        Resource resource = Resource.newResource(config);
        properties.load(resource.getInputStream());

        jdbcDriver = properties.getProperty("jdbcDriver");
        url = properties.getProperty("url");
        userName = properties.getProperty("userName");
        password = properties.getProperty("password");
        userTable = properties.getProperty("userTable");
        userTableLogin = properties.getProperty("userTableLogin");
        userTablePassword = properties.getProperty("userTablePassword");
        passwordPrefix = properties.getProperty("passwordPrefix");
        roleTable = properties.getProperty("roleTable");
        roleTableUser = properties.getProperty("roleTableUser");
        roleTableRole = properties.getProperty("roleTableRole");
        cacheTime = new Integer(properties.getProperty("cacheTime"));

        if (jdbcDriver == null || jdbcDriver.equals("")
                || url == null
                || url.equals("")
                || userName == null
                || userName.equals("")
                || password == null
                || cacheTime < 0) {
            LOG.warn("UserRealm " + getName() + " has not been properly configured");
        }
        cacheTime *= 1000;
        lastHashPurge = 0;
        userSql = "select " + userTablePassword + " from " 
                + userTable + " where " + userTableLogin + " = ? ";
        roleSql = "select " + roleTableRole + " from " + roleTable + " where " 
                + roleTableUser + " = ?";

        Loader.loadClass(this.getClass(), jdbcDriver).newInstance();
        super.doStart();
    }

    public void setConfig(String config) {
        if (isRunning()) {
            throw new IllegalStateException("Running");
        }
        this.config = config;
       LOG.info("set config: " + config, os);
    }

    public void connectDatabase() {
        try {
            Class.forName(jdbcDriver);
            con = DriverManager.getConnection(url, userName, password);
        } catch (SQLException e) {
            LOG.warn("UserRealm " + getName() + " could not connect to database; will try later", e);
        } catch (ClassNotFoundException e) {
            LOG.warn("UserRealm " + getName() + " could not connect to database; will try later", e);
        }
    }

    @Override
    public UserIdentity login(String username, Object credentials) {
        long now = System.currentTimeMillis();
        if (now - lastHashPurge > cacheTime || cacheTime == 0) {
            _users.clear();
            lastHashPurge = now;
            closeConnection();
        }
        return super.login(username, credentials);
    }

    @Override
    protected void loadUsers() {
    }

    @Override
    protected UserIdentity loadUser(String username) {
        try {
            if (null == con) {
                connectDatabase();
            }

            if (null == con) {
                throw new SQLException("Can't connect to database");
            }

            PreparedStatement stat = con.prepareStatement(userSql);
            stat.setString(1, username);
            ResultSet rs = stat.executeQuery();

            if (rs.next()) {
                String credentials = passwordPrefix + rs.getString(userTablePassword);
                stat.close();

                stat = con.prepareStatement(roleSql);
                stat.setString(1, username);
                rs = stat.executeQuery();
                List<String> roles = new ArrayList<String>();
                while (rs.next()) {
                    roles.add(rs.getString(1));
                }
                stat.close();
                
                return putUser(username, Credential.getCredential(credentials), roles.toArray(new String[roles.size()]));
            }
        } catch (SQLException e) {
            LOG.warn("UserRealm " + getName() + " could not load user information from database", e);
        } finally {
            closeConnection();
        }
        return null;
    }

    private void closeConnection() {
        if (con != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Closing db connection for kfsJDBCUserRealm");
            }
            try {
                con.close();
            } catch (Exception e) {
                LOG.ignore(e);
            }
        }
        con = null;
    }

}
