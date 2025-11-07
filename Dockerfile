# build stage
FROM eclipse-temurin:21-jdk AS builder
WORKDIR /app
COPY . .

RUN chmod +x ./gradlew
RUN ./gradlew clean build -x test

RUN mkdir -p build/libs && \
    ls -al build/libs && \
    sh -c 'f=$(ls -S build/libs/*.jar | head -n 1); cp "$f" build/libs/app.jar' && \
    ls -al build/libs
    
# runtime stage
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=builder /app/build/libs/app.jar /app/app.jar
RUN chmod 644 /app/app.jar
ENTRYPOINT ["java","-jar","/app/app.jar"]
