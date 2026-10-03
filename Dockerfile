FROM eclipse-temurin:21-jdk AS build
WORKDIR /src
COPY mvnw pom.xml ./
COPY .mvn .mvn
RUN ./mvnw -q -B dependency:go-offline
COPY src src
COPY policy policy
COPY feed feed
COPY testdata testdata
RUN ./mvnw -q -B -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app
RUN useradd --system --uid 10001 aigate && mkdir -p /app/data /app/policy && chown -R aigate /app
COPY --from=build /src/target/aigate-*.jar /app/aigate.jar
COPY --chown=aigate policy /app/policy
USER aigate
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/aigate.jar"]
