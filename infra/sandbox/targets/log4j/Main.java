package ai.evidencegraph.sandbox;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

/**
 * Intentionally vulnerable Log4j 2.14.1 HTTP server for controlled defensive testing.
 * Exclusively designed for the air-gapped EvidenceGraphAI sandbox environment.
 */
public class Main {
    private static final Logger logger = LogManager.getLogger(Main.class);
    private static final int PORT = 8080;

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/", new VulnerableHandler());
        server.setExecutor(null);
        System.out.println("[Log4j-Target] Starting vulnerable server on port " + PORT);
        logger.info("Log4j vulnerable test service initialized on port {}", PORT);
        server.start();
    }

    static class VulnerableHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Vulnerable header logging (CVE-2021-44228 trigger)
            String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
            String xApiVersion = exchange.getRequestHeaders().getFirst("X-Api-Version");

            if (userAgent != null) {
                logger.info("Received request with User-Agent: {}", userAgent);
            }
            if (xApiVersion != null) {
                logger.info("Received request with X-Api-Version: {}", xApiVersion);
            }

            String response = "{\"status\": \"ok\", \"service\": \"log4j-vulnerable-app\"}\n";
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }
    }
}
