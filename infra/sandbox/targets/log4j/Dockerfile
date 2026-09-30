# Intentionally vulnerable Log4j 2.14.1 Target Container
# Strictly for isolated, air-gapped defensive replay testing in EvidenceGraphAI.
FROM maven:3.8.6-openjdk-11 AS build
WORKDIR /app
COPY pom.xml .
COPY Main.java ./src/main/java/ai/evidencegraph/sandbox/Main.java
RUN mvn clean package -DskipTests

FROM openjdk:11-jre-slim
WORKDIR /app
COPY --from=build /app/target/log4j-vulnerable-app-1.0.0.jar ./app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
