# Tidegate's filter asks this worker over HTTP on the stack's private network.
bind_socket = "*:11333";
# The filter sends message bytes, never file paths: refuse "scan this file" requests on the network listener.
allow_file_and_shm_inputs = false;
