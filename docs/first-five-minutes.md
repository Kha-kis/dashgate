# Try DashGate in five minutes

DashGate puts your self-hosted web apps in one dashboard. Each person signs in, and you decide which groups can see each app. Discovery finds routes, but an admin reviews them before they appear on the dashboard.

## 1. Start a local instance

You need Docker and an available port 1738. This example keeps DashGate's database and configuration in a `config` directory beside your terminal:

```bash
mkdir -p config
docker run -d \
  --name dashgate \
  -p 1738:1738 \
  -v "$(pwd)/config:/config" \
  --restart unless-stopped \
  ghcr.io/kha-kis/dashgate:1.5.11
```

Open <http://localhost:1738> and complete the setup wizard. Local authentication is the simplest way to try the app; you can configure another supported provider later. Keep the `config` directory private because it contains your DashGate database and secrets.

## 2. Add an app

Sign in as the administrator, open **Settings > Admin > Content**, and select **Add App**. Enter the name and URL of a service you run, then choose a category. Assign access groups if only some signed-in users should see it. An app without groups is visible to every authenticated user.

The dashboard groups your apps by category and checks their health in the background. Open **Settings > Admin > Users > Explain App Access** to see why a saved user can or cannot see a particular app.

## 3. Try discovery when you have a source

Open **Settings > Admin > Discovery** and enable a source you already use, such as Nginx or Docker. For Docker, use a [restricted socket proxy](../README.md#docker); a read-only bind mount of the Docker socket does not restrict Docker API commands. For Nginx, mount the configuration directory read-only and point DashGate to that directory.

Found routes appear under **Settings > Admin > Content > Discovered Apps**. Search or filter the inbox, inspect a route, and configure its category and access groups before publishing it. Routes already on the dashboard appear under **Already added**. You can dismiss unwanted routes or create an ignore rule for repeated paths such as health checks. Discovery never publishes a route automatically.

## What to read next

- [Authentication options](../README.md#authentication)
- [Discovery sources and labels](../README.md#app-discovery)
- [Backup, upgrade, and recovery](deployment.md)
- [Security recommendations](../SECURITY.md)
