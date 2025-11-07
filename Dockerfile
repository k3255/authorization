# build stage
FROM eclipse-temurin:21-jdk AS builder
WORKDIR /app
COPY . .
RUN ./gradlew clean build -x test

# runtime stage
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=builder /app/build/libs/your-app.jar /app/app.jar
CMD ["java", "-jar", "/app/app.jar"]
