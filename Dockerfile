FROM scottyhardy/docker-wine

# Install any additional dependencies if needed
USER root
RUN apt-get update && apt-get install -y git

# Switch back to wine user
USER wine
WORKDIR /home/wine

# Copy your Windows binary
COPY android-quality-checker.exe .

# Make it executable
RUN chmod +x android-quality-checker.exe