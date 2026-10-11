
require("dotenv").config();

const crypto = require("node:crypto");
const express = require("express");
const Database = require("better-sqlite3");
const {
  Client,
  GatewayIntentBits,
  Events,
  REST,
  Routes,
  SlashCommandBuilder,
  PermissionFlagsBits,
  MessageFlags,
} = require("discord.js");

const {
  BOT_TOKEN,
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI,
  PORT = "3000",
  STATE_SECRET,
  TOKEN_ENCRYPTION_KEY,
  TEST_GUILD_ID,
} = process.env;

const required = {
  BOT_TOKEN,
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI,
  STATE_SECRET,
  TOKEN_ENCRYPTION_KEY,
  TEST_GUILD_ID,
};

for (const [name, value] of Object.entries(required)) {
  if (!value || value.startsWith("YOUR_")) {
    throw new Error(`Missing or placeholder environment value: ${name}`);
  }
}

const encryptionKey = Buffer.from(TOKEN_ENCRYPTION_KEY, "base64");

if (encryptionKey.length !== 32) {
  throw new Error(
    "TOKEN_ENCRYPTION_KEY must be a Base64-encoded 32-byte key."
  );
}

const app = express();
const db = new Database("bot-data.sqlite");

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS authorizations (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (guild_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS dm_preferences (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    opted_in INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (guild_id, user_id)
  );
`);

const client = new Client({
  intents: [GatewayIntentBits.Guilds],
});

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    encryptionKey,
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(text, "utf8"),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return [
    iv.toString("base64"),
    tag.toString("base64"),
    encrypted.toString("base64"),
  ].join(".");
}

function decrypt(value) {
  const [ivText, tagText, dataText] = value.split(".");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    encryptionKey,
    Buffer.from(ivText, "base64")
  );

  decipher.setAuthTag(Buffer.from(tagText, "base64"));

  return Buffer.concat([
    decipher.update(Buffer.from(dataText, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

function createState(userId, guildId) {
  const payload = Buffer.from(
    JSON.stringify({
      userId,
      guildId,
      issuedAt: Date.now(),
      nonce: crypto.randomBytes(16).toString("hex"),
    })
  ).toString("base64url");

  const signature = crypto
    .createHmac("sha256", STATE_SECRET)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

function verifyState(state) {
  if (typeof state !== "string") {
    throw new Error("Missing OAuth state.");
  }

  const parts = state.split(".");
  if (parts.length !== 2) {
    throw new Error("Invalid OAuth state.");
  }

  const [payload, signature] = parts;

  const expected = crypto
    .createHmac("sha256", STATE_SECRET)
    .update(payload)
    .digest();

  let supplied;
  try {
    supplied = Buffer.from(signature, "base64url");
  } catch {
    throw new Error("Invalid OAuth signature.");
  }

  if (
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(supplied, expected)
  ) {
    throw new Error("OAuth state signature did not match.");
  }

  const data = JSON.parse(
    Buffer.from(payload, "base64url").toString("utf8")
  );

  if (
    !data.userId ||
    !data.guildId ||
    !data.issuedAt ||
    Date.now() - data.issuedAt > 15 * 60 * 1000 ||
    data.issuedAt > Date.now() + 60 * 1000
  ) {
    throw new Error("OAuth state expired or is invalid.");
  }

  return data;
}

async function exchangeCode(code) {
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
  });

  const response = await fetch(
    "https://discord.com/api/v10/oauth2/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    }
  );

  const result = await response.json();

  if (!response.ok) {
    throw new Error(
      `OAuth token exchange failed: ${JSON.stringify(result)}`
    );
  }

  return result;
}

async function getValidAccessToken(row) {
  if (row.expires_at > Date.now() + 60_000) {
    return decrypt(row.access_token);
  }

  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: decrypt(row.refresh_token),
  });

  const response = await fetch(
    "https://discord.com/api/v10/oauth2/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    }
  );

  const result = await response.json();

  if (!response.ok) {
    throw new Error("Token refresh failed; the user may need to authorize again.");
  }

  db.prepare(`
    UPDATE authorizations
    SET access_token = ?,
        refresh_token = ?,
        expires_at = ?
    WHERE guild_id = ? AND user_id = ?
  `).run(
    encrypt(result.access_token),
    encrypt(result.refresh_token || decrypt(row.refresh_token)),
    Date.now() + result.expires_in * 1000,
    row.guild_id,
    row.user_id
  );

  return result.access_token;
}

app.get("/", (_req, res) => {
  res.type("text").send("Discord bot OAuth callback server is running.");
});

app.get("/oauth/callback", async (req, res) => {
  try {
    if (req.query.error) {
      return res.status(400).send(
        "Discord authorization was cancelled or denied. You can close this page."
      );
    }

    const { code, state } = req.query;

    if (typeof code !== "string") {
      return res.status(400).send("Missing authorization code.");
    }

    const stateData = verifyState(state);
    const tokenData = await exchangeCode(code);

    const userResponse = await fetch(
      "https://discord.com/api/v10/users/@me",
      {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
        },
      }
    );

    if (!userResponse.ok) {
      throw new Error("Could not identify the authorizing Discord user.");
    }

    const user = await userResponse.json();

    if (user.id !== stateData.userId) {
      return res.status(403).send(
        "The Discord account does not match the user who requested this link."
      );
    }

    if (!tokenData.refresh_token) {
      throw new Error("Discord did not return a refresh token.");
    }

    db.prepare(`
      INSERT INTO authorizations (
        guild_id, user_id, access_token, refresh_token, expires_at
      )
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(guild_id, user_id) DO UPDATE SET
        access_token = excluded.access_token,
        refresh_token = excluded.refresh_token,
        expires_at = excluded.expires_at
    `).run(
      stateData.guildId,
      user.id,
      encrypt(tokenData.access_token),
      encrypt(tokenData.refresh_token),
      Date.now() + tokenData.expires_in * 1000
    );

    return res.type("html").send(
      "<h2>Authorization successful.</h2><p>You can close this page and return to Discord.</p>"
    );
  } catch (error) {
    console.error("OAuth callback error:", error.message);
    return res.status(400).send(
      "Authorization could not be completed. Check the bot console for details."
    );
  }
});

const commands = [
  new SlashCommandBuilder()
    .setName("adduser")
    .setDescription("Get your personal authorization link"),

  new SlashCommandBuilder()
    .setName("addmembers")
    .setDescription("Add users who authorized this server")
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),

  new SlashCommandBuilder()
    .setName("dmoptin")
    .setDescription("Opt in to direct messages from this server's bot"),

  new SlashCommandBuilder()
    .setName("dmoptout")
    .setDescription("Opt out of direct messages from this server's bot"),

  new SlashCommandBuilder()
    .setName("dmuser")
    .setDescription("DM one opted-in member")
    .addUserOption(option =>
      option
        .setName("user")
        .setDescription("Member to message")
        .setRequired(true)
    )
    .addStringOption(option =>
      option
        .setName("message")
        .setDescription("Message to send")
        .setRequired(true)
        .setMaxLength(2000)
    )
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),

  new SlashCommandBuilder()
    .setName("dmall")
    .setDescription("DM all opted-in members")
    .addStringOption(option =>
      option
        .setName("message")
        .setDescription("Message to send")
        .setRequired(true)
        .setMaxLength(2000)
    )
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
].map(command => command.toJSON());

async function registerCommands() {
  const rest = new REST({ version: "10" }).setToken(BOT_TOKEN);

  await rest.put(
    Routes.applicationGuildCommands(CLIENT_ID, TEST_GUILD_ID),
    { body: commands }
  );

  console.log("Slash commands registered in the test server.");
}

function isAdministrator(interaction) {
  return interaction.memberPermissions?.has(
    PermissionFlagsBits.Administrator
  );
}

async function addAuthorizedMembers(interaction) {
  const guildId = interaction.guildId;

  const rows = db.prepare(`
    SELECT * FROM authorizations WHERE guild_id = ?
  `).all(guildId);

  if (!rows.length) {
    return interaction.editReply(
      "No users have authorized this server yet. Ask them to use `/adduser` first."
    );
  }

  let added = 0;
  let alreadyPresent = 0;
  let failed = 0;

  for (const row of rows) {
    try {
      const accessToken = await getValidAccessToken(row);

      const response = await fetch(
        `https://discord.com/api/v10/guilds/${guildId}/members/${row.user_id}`,
        {
          method: "PUT",
          headers: {
            Authorization: `Bot ${BOT_TOKEN}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ access_token: accessToken }),
        }
      );

      if (response.status === 201) {
        added++;
      } else if (response.status === 204) {
        alreadyPresent++;
      } else {
        failed++;
        console.error(
          `Could not add user ${row.user_id}:`,
          response.status,
          await response.text()
        );
      }
    } catch (error) {
      failed++;
      console.error(`Failed for user ${row.user_id}:`, error.message);
    }
  }

  return interaction.editReply(
    `Finished. Added: ${added}. Already in server: ${alreadyPresent}. Failed: ${failed}.`
  );
}

async function sendToOptedInUser(guildId, userId, message) {
  const preference = db.prepare(`
    SELECT opted_in FROM dm_preferences
    WHERE guild_id = ? AND user_id = ?
  `).get(guildId, userId);

  if (!preference || preference.opted_in !== 1) {
    return { sent: false, reason: "not opted in" };
  }

  const guild = client.guilds.cache.get(guildId);
  if (!guild) {
    return { sent: false, reason: "server unavailable" };
  }

  const member = await guild.members.fetch(userId).catch(() => null);

  if (!member) {
    return { sent: false, reason: "not a server member" };
  }

  await member.send(message);
  return { sent: true };
}

client.on(Events.InteractionCreate, async interaction => {
  if (!interaction.isChatInputCommand()) return;

  if (!interaction.inGuild()) {
    return interaction.reply({
      content: "Use this command inside the server.",
      flags: MessageFlags.Ephemeral,
    });
  }

  try {
    if (interaction.commandName === "adduser") {
      const state = createState(interaction.user.id, interaction.guildId);

      const url = new URL("https://discord.com/oauth2/authorize");
      url.searchParams.set("client_id", CLIENT_ID);
      url.searchParams.set("redirect_uri", REDIRECT_URI);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("scope", "identify guilds.join");
      url.searchParams.set("state", state);
      url.searchParams.set("prompt", "consent");

      return interaction.reply({
        content: `Your personal authorization link (valid for 15 minutes):\n${url.toString()}`,
        flags: MessageFlags.Ephemeral,
      });
    }

    if (interaction.commandName === "addmembers") {
      if (!isAdministrator(interaction)) {
        return interaction.reply({
          content: "Administrator permission is required.",
          flags: MessageFlags.Ephemeral,
        });
      }

      await interaction.deferReply({
        flags: MessageFlags.Ephemeral,
      });

      return await addAuthorizedMembers(interaction);
    }

    if (interaction.commandName === "dmoptin") {
      db.prepare(`
        INSERT INTO dm_preferences (guild_id, user_id, opted_in)
        VALUES (?, ?, 1)
        ON CONFLICT(guild_id, user_id) DO UPDATE SET opted_in = 1
      `).run(interaction.guildId, interaction.user.id);

      return interaction.reply({
        content: "You've opted in to direct messages from this server's bot. Use `/dmoptout` to opt out.",
        flags: MessageFlags.Ephemeral,
      });
    }

    if (interaction.commandName === "dmoptout") {
      db.prepare(`
        INSERT INTO dm_preferences (guild_id, user_id, opted_in)
        VALUES (?, ?, 0)
        ON CONFLICT(guild_id, user_id) DO UPDATE SET opted_in = 0
      `).run(interaction.guildId, interaction.user.id);

      return interaction.reply({
        content: "You've opted out of direct messages from this server's bot.",
        flags: MessageFlags.Ephemeral,
      });
    }

    if (interaction.commandName === "dmuser") {
      if (!isAdministrator(interaction)) {
        return interaction.reply({
          content: "Administrator permission is required.",
          flags: MessageFlags.Ephemeral,
        });
      }

      await interaction.deferReply({
        flags: MessageFlags.Ephemeral,
      });

      const user = interaction.options.getUser("user", true);
      const message = interaction.options.getString("message", true);

      try {
        const result = await sendToOptedInUser(
          interaction.guildId,
          user.id,
          message
        );

        return interaction.editReply(
          result.sent
            ? `Message sent to ${user.tag}.`
            : `Message not sent: ${result.reason}.`
        );
      } catch {
        return interaction.editReply(
          "Could not send the DM. The user may have DMs disabled."
        );
      }
    }

    if (interaction.commandName === "dmall") {
      if (!isAdministrator(interaction)) {
        return interaction.reply({
          content: "Administrator permission is required.",
          flags: MessageFlags.Ephemeral,
        });
      }

      await interaction.deferReply({
        flags: MessageFlags.Ephemeral,
      });

      const message = interaction.options.getString("message", true);

      const recipients = db.prepare(`
        SELECT user_id FROM dm_preferences
        WHERE guild_id = ? AND opted_in = 1
      `).all(interaction.guildId);

      let sent = 0;
      let failed = 0;

      for (const recipient of recipients) {
        try {
          const result = await sendToOptedInUser(
            interaction.guildId,
            recipient.user_id,
            message
          );

          if (result.sent) {
            sent++;
          } else {
            failed++;
          }
        } catch {
          failed++;
        }
      }

      return interaction.editReply(
        `Bulk DM complete. Sent: ${sent}. Not sent: ${failed}. Only opted-in members were contacted.`
      );
    }
  } catch (error) {
    console.error("Command error:", error);

    const message = "Something went wrong. Check the bot console for details.";

    if (interaction.deferred || interaction.replied) {
      await interaction.editReply(message).catch(() => {});
    } else {
      await interaction.reply({
        content: message,
        flags: MessageFlags.Ephemeral,
      }).catch(() => {});
    }
  }
});

client.once(Events.ClientReady, async readyClient => {
  console.log(`Logged in as ${readyClient.user.tag}`);

  try {
    await registerCommands();
  } catch (error) {
    console.error("Could not register slash commands:", error.message);
  }
});

app.listen(Number(PORT), "127.0.0.1", () => {
  console.log(`OAuth callback server listening on http://localhost:${PORT}`);
});

client.login(BOT_TOKEN).catch(error => {
  console.error("Discord login failed:", error.message);
  process.exitCode = 1;
});
