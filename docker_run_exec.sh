docker run -it --rm \
  -v /Users/user/Projects/android/someproject-android:/home/wine/test-project \
  android-checker-test \
  wine android-quality-checker.bin /home/wine/test-project


# docker run --rm -it \
#   -v $(pwd):/app \
#   -w /app \
#   scottyhardy/docker-wine \
#   wine android-quality-checker.bin