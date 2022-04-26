# SSH Agent

This is an implementation of the SSH Agent protocol,
used by the canonical `ssh-agent` program in the OpenSSH distribution
to hold keys and perform signature operations.

I wanted to work on an SSH agent becuase I recently had to SSH into
several thousand machines in one operation, and found that the
performance bottleneck was in the stock ssh-agent program. The stock
agent runs in a single thread and needs to sign each request
individually. I hope to use this project to test whether the agent can
be made multithreaded and improve performance when performing extremely
large bulk SSH operations.

## Running the agent

**Please don't use this in production.**
This is an experiment/learning project and not
validated as a cryptosystem at all.

SSH controls which agent is in use with the `SSH_AUTH_SOCK` variable, so
to use an alternate agent set that variable to the auth socket.

By default, this project listens on `./socket` in the working directory,
so to use it:

In one terminal;
```
~/ssh-agent $ sbt run
[info] welcome to sbt 1.6.2 (Homebrew Java 18)
[info] loading global plugins from /Users/user/.sbt/1.0/plugins
[info] loading project definition from /Users/user/ssh-agent/project
[info] loading settings for project root from build.sbt ...
[info] set current project to SshAgent (in build file:/Users/user/ssh-agent)
[info] running com.pygostylia.sshagent.Server
Listening on ./socket
```

In another terminal in the same directory;
```
~/ssh-agent $ SSH_AUTH_SOCK=./socket ssh-add
Identity added: /Users/user/.ssh/id_rsa (user@hostname.local)
~/ssh-agent $ SSH_AUTH_SOCK=./socket ssh-add -l
3072 SHA256:xDfojB0NHXp+6H6bRdJbpBB+Sarpp64CL6w9mqUbyxY user@hostname.local (RSA)
~/ssh-agent $ SSH_AUTH_SOCK=./socket ssh some-other-machine.com
user@some-other-machine ~ $
```

This project supports only a small set of ssh-agent features,
not including agent locking, tokens, constraints, lifetimes,
extensions, or removing keys from the agent.

## References

Protocol documentation:
[SSH Agent Protocol](https://tools.ietf.org/id/draft-miller-ssh-agent-01.html)
