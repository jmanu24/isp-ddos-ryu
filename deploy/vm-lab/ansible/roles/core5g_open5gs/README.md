# Open5GS startup

The systemd service starts the existing docker-5gc:latest image with
`docker compose up --no-build --pull never 5gc`. Provisioning builds the
initial image only when it is missing. A failed build must not trigger an
automatic compilation loop during VM startup.

To deliberately rebuild after changing Open5GS sources or image contents:

```bash
sudo systemctl stop open5gs-5gc
cd /opt/srsRAN_Project/docker
sudo docker compose build 5gc
sudo systemctl start open5gs-5gc
```

Check `docker ps --filter name=open5gs_5gc`, the container health, and
`docker exec open5gs_5gc pgrep -c open5gs-` (at least eight processes).
The core5g root disk was expanded online from 20 to 40 GiB after the build
failed while extracting an image layer with `no space left on device`.
The ignored failure when deleting a missing ogstun interface is harmless.
