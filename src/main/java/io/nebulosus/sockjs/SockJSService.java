package io.nebulosus.sockjs;

import io.jsync.Async;
import io.jsync.app.core.Cluster;
import io.jsync.app.core.Config;
import io.jsync.app.core.Logger;
import io.jsync.app.core.service.ClusterService;
import io.jsync.eventbus.EventBus;
import io.jsync.http.HttpServer;
import io.jsync.json.JsonObject;
import io.jsync.sockjs.SockJSServer;

/**
 * This provides the critical layer that allows clients to communicate with Nebulosus.
 */
public class SockJSService implements ClusterService {

    final public static int DEFAULT_PORT = 6174;

    private Async async = null;
    private EventBus eventBus = null;
    private HttpServer httpServer = null;
    private SockJSServer sockJSServer = null;

    @Override
    public void start(Cluster owner) {
        async = owner.async();
        eventBus = owner.eventBus();

        Logger logger = owner.logger();

        Config config = owner.config();

        JsonObject sockServerConfig = config.rawConfig().getObject("sock", new JsonObject());

        int serverPort = sockServerConfig.getInteger("port", DEFAULT_PORT);
        String serverHost = sockServerConfig.getString("host", "127.0.0.1");

        sockServerConfig.putNumber("port", serverPort);
        sockServerConfig.putString("host", serverHost);

        config.rawConfig().putObject("sock", sockServerConfig);

        config.save();

        httpServer = async.createHttpServer();
        sockJSServer = owner.async().createSockJSServer(httpServer);

        JsonObject sockJSConfig = new JsonObject().putString("prefix", "/nebulosus.sock");

        // Let's create a handler to handle requests properly.
        SockJSHandler sockJSHandler = new SockJSHandler(owner);

        sockJSServer.installApp(sockJSConfig, sockJSHandler);

        httpServer.setMaxWebSocketFrameSize(262144);

        httpServer.listen(serverPort, serverHost, asyncResult -> {
            if (!asyncResult.succeeded()) {
                logger.fatal("Could not start SockJSService on " + serverHost + ":" + serverPort);
                return;
            }
            logger.info("SockJSService Started on " + serverHost + ":" + serverPort);
        });
    }

    @Override
    public void stop() {

    }

    @Override
    public boolean running() {
        return false;
    }

    @Override
    public String name() {
        return "SockJSAPI";
    }
}
