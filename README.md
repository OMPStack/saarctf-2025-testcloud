# Saarctf Testsetup

This repository is used to create a simplified version of the saarctf cloud-hosted setup.
When the game starts, you will get ssh access to a vm and that's it.
This repo sets up this VM together with a game gateway, so you have something to test your scripts.
The vulnbox contains a dummy service and the gateway will run exploit/checker traffic against it.

## Requirements

* Cloudflare account with a registered domain
* Hetzner account with the quota to create two small VMs.
* Local install of [OpenTofu](https://opentofu.org/).
* Install the requirements: `tofu init`

## How to run this

1. Create project in Hetzner Cloud.
2. Add a new API Token (Read&Write) under **Security** > **API tokens**. Note it as the `HCLOUD_TOKEN` in the .env file.
3. Get the Cloudflare API Token and Zone ID by going to the Overview page of your registered domain and go to the bottom
   of the right most column.

4. Create a `.env` file with the following content:

```dotenv
export HCLOUD_TOKEN=
export CLOUDFLARE_API_TOKEN=
export CLOUDFLARE_ZONE_ID=
```

5. Source the config and create the VMs:

```bash
source .env
tofu apply
```

6. Provision the system using:
```bash
ansible-galaxy install -r requirements.yml
ansible-playbook setup.yml
```

## Monitoring

See what the checker `/opt/dummy_checker/checker.py` is doing:
```bash
journalctl -f -u dummy_checker.service
```