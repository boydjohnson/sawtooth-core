FROM lint:latest

ENV LIBZMQ_PREFIX /usr

RUN ln -s /usr/bin/python3 /usr/bin/python

RUN /root/.cargo/bin/rustup toolchain add nightly

RUN /root/.cargo/bin/rustup default nightly

WORKDIR /project/perf-validator
