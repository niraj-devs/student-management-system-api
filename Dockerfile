# Stage 1: Build
FROM maven:3.9-eclipse-temurin-17 AS build

WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean package -DskipTests


# Stage 2: Run
FROM eclipse-temurin:17-jre

RUN useradd --system appuser

WORKDIR /app

COPY --from=build /app/target/education-platform-0.0.1-SNAPSHOT.jar app.jar

USER appuser

EXPOSE 8080



CMD ["java", "-jar", "app.jar"]