# post-init (work in progress)

Post-Init is a set of tools that allows you to easily connect to, provision, and interact with cloud instances after they have been created. 

With post-init, instances connect to a central (self-hosted) relay server and receive provisioning instructions either in real-time using the client, or from preconfigured jobs. Send commands or shell scripts to instances as soon as they start up, and easily copy files back and forth. It is easily installed during cloud-init and runs asynchronously after cloud-init completes. 
