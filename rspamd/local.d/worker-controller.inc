# Tidegate doesn't use Rspamd's web interface. Keep it inside the container (rspamc learn_spam still works there).
bind_socket = "localhost:11334";
allow_file_and_shm_inputs = false;
