FROM openjdk:21-jdk-slim as builder

WORKDIR /app

COPY . .

RUN ./gradlew clean build -x test

FROM openjdk:21-jre-slim-bookworm

WORKDIR /app

COPY --from=builder /app/build/libs/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
