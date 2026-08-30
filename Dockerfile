# DFTK — turnkey forensic toolkit image with disk-image & SRUM support.
#
# DFTK keeps zero mandatory dependencies, but the optional disk/SRUM extras
# (pyewf, pytsk3, python-libesedb) need native system libraries to build. This
# image provides them so `pip install ".[all]"` succeeds and the headline
# capabilities (E01 inventory, filesystem traversal, Windows SRUM) are available
# out of the box instead of returning UNSUPPORTED.
#
# Build:
#   docker build -t dftk .
# Run (read-only over a mounted evidence file):
#   docker run --rm -v "$PWD:/evidence:ro" dftk \
#       run image.e01_inventory --params '{"path":"/evidence/disk.E01"}'
# Or drop into a shell:
#   docker run --rm -it -v "$PWD:/evidence:ro" --entrypoint bash dftk

FROM python:3.12-slim

# Native build dependencies for the optional disk/SRUM extras.
#   libewf-dev   -> pyewf  (E01/EWF images)
#   libtsk-dev   -> pytsk3 (filesystem traversal)
#   libesedb-dev -> python-libesedb (Windows SRUM / ESE databases)
# If the PyPI wheels already cover your platform you can drop these, but they
# guarantee a clean build regardless of wheel availability.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libewf-dev libtsk-dev libesedb-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install DFTK with ALL optional capabilities enabled.
COPY . /app
RUN pip install --no-cache-dir ".[all]"

ENTRYPOINT ["dftk"]
CMD ["--help"]
