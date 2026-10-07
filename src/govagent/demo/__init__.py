"""Live demo: an advisor chat, a supervisor console and an audit viewer on top of the gateway service.

This process plays three roles that are separate in production: the web front-end, a dev identity
provider (it mints tokens with the dev signing seed), and the agent runtime. It has NO backend
access and no policy: every action goes over HTTP to the gateway service.
"""
