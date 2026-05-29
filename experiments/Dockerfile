# Stage 1: build DL-Learner CLI from the orbis-security fork
FROM maven:3.9-eclipse-temurin-21 AS builder

RUN git clone --depth 1 https://github.com/orbis-security/DL-Learner.git /opt/dl-learner-src

WORKDIR /opt/dl-learner-src

# Redirect broken/HTTP repos to HTTPS or Central so Maven doesn't cache empty JARs
COPY maven-settings.xml /root/.m2/settings.xml

# Pass 1: resolve dependencies (tolerates failures from dead repos, may leave empty JARs)
RUN mvn dependency:resolve -pl interfaces -am -q 2>/dev/null || true

# Purge empty/corrupt JARs and stale metadata so Maven retries from remaining repos (primarily Central)
RUN find /root/.m2/repository -name "*.jar" -empty -delete && \
    find /root/.m2/repository -name "*.lastUpdated" -delete

# Pass 2: full build with clean cache
RUN mvn package -pl interfaces -am -DskipTests -Prelease -q

# Locate and extract the binary distribution (version-agnostic)
RUN set -eux; \
    archive=$(find interfaces/target -maxdepth 1 -name "dllearner-*.tar.gz" | head -1); \
    mkdir -p /opt/dl-learner; \
    tar -xzf "$archive" --strip-components=1 -C /opt/dl-learner


# Stage 2: lightweight runtime image
FROM eclipse-temurin:21-jre-alpine

RUN apk add --no-cache bash

# cglib (used by jena-sparql-api) needs reflective access to ClassLoader blocked by Java 9+ modules
ENV JDK_JAVA_OPTIONS="--add-opens java.base/java.lang=ALL-UNNAMED -Xmx8g"

COPY --from=builder /opt/dl-learner /opt/dl-learner
RUN chmod +x /opt/dl-learner/bin/cli

COPY . /app/experiments/
RUN chmod +x /app/experiments/run_experiments.sh

# Mount a host directory here to retrieve logs after the run:
#   docker run --rm -v "$(pwd)/results:/app/results" maeco-experiments
VOLUME ["/app/results"]

WORKDIR /app
ENTRYPOINT ["/app/experiments/run_experiments.sh"]
