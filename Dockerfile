FROM eclipse-temurin:21-jdk

WORKDIR /app

# Copy source and static files
COPY DetectionEngine.java Server.java login.html monitor.html ./

# Compile — no external deps, just the JDK
RUN javac DetectionEngine.java Server.java

EXPOSE 8080

CMD ["java", "Server"]
