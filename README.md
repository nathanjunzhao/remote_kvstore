# Remote Key-Value Store

This project is a high-performance, persistent key-value store built from the ground up in C. It is engineered to serve as a reliable, standalone caching service for larger, distributed applications.

The core of the system is designed for complete data integrity. It uses an append-only log and a state-recovery mechanism to ensure that the data store can survive an unexpected crash without any data loss. For performance, it features an in-memory hash index for near-instantaneous data lookups and an automated garbage collection system to efficiently manage storage. The entire store is exposed as a network service via an HTTP API, allowing any application to use it as a fast, remote cache for expensive computations or database queries.
