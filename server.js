import express from "express";
import cookieParser from "cookie-parser";
import { config } from "dotenv";
import path from "path";
import * as discord from "./discord.js";
import * as storage from "./storage.js";
import {
    connectDB,
    getUser,
    updateUser,
    getAllowedUsers,
    db,
} from "./database.js";

config();

const __dirname = path.dirname(new URL(import.meta.url).pathname);
const app = express();
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(express.static("public"));
app.use(express.json());

// Global allowedIDs object
let allowedIDs = {
    is_dev: [],
    is_mod: [],
    is_ads: [],
    is_owner: [],
    is_contributor: [],
};

/**
 * Updates the Discord metadata for the user.
 * It sets each role as a boolean based on the hardcoded allowed IDs.
 */
async function updateMetadata(userId) {
    const tokens = await storage.getDiscordTokens(userId);
    if (!tokens) {
        console.error(`No tokens found for user ${userId}`);
        return;
    }

    const user = await getUser(userId);
    if (!user) {
        console.error(`User ${userId} not found in database`);
        return;
    }

    const metadata = {
        is_dev: user.is_dev,
        is_mod: user.is_mod,
        is_ads: user.is_ads,
        is_owner: user.is_owner,
        is_contributor: user.is_contributor,
    };

    console.log(`📡 Pushing metadata for ${userId}:`, metadata);
    try {
        await discord.pushMetadata(userId, tokens, metadata);
        console.log(`✅ Successfully updated metadata for ${userId}`);
    } catch (e) {
        console.error(`❌ Error updating metadata for ${userId}:`, e);
    }
}

app.get("/", (req, res) => res.send("👋"));

app.get("/linked-role", async (req, res) => {
    const { url, state } = discord.getOAuthUrl();
    res.cookie("clientState", state, { maxAge: 5 * 60 * 1000, signed: true });
    res.redirect(url);
});

app.get("/discord-oauth-callback", async (req, res) => {
    try {
        const code = req.query["code"];
        const discordState = req.query["state"];
        const { clientState } = req.signedCookies;

        if (clientState !== discordState) {
            console.error("State verification failed.");
            return res.sendStatus(403);
        }

        const tokens = await discord.getOAuthTokens(code);
        const userData = await discord.getUserData(tokens);

        if (!userData || !userData.id) {
            throw new Error("Discord API'den geçersiz kullanıcı verisi alındı");
        }

        const userId = userData.id;
        await storage.storeDiscordTokens(userId, {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_at: Date.now() + tokens.expires_in * 1000,
        });

        // Update metadata based on hardcoded allowed IDs.
        await updateMetadata(userId);
        res.sendFile(path.resolve(__dirname, "discord-oauth-callback.html"));
    } catch (e) {
        console.error("Error in OAuth callback:", e);
        res.sendStatus(500);
    }
});

app.post("/update-metadata", async (req, res) => {
    try {
        const userId = req.body.userId;
        await updateMetadata(userId);
        res.sendStatus(204);
    } catch (e) {
        console.error("Error in /update-metadata:", e);
        res.sendStatus(500);
    }
});

app.post("/remove-metadata", async (req, res) => {
    try {
        const userId = req.body.userId;
        const tokens = await storage.getDiscordTokens(userId);

        if (!tokens) {
            console.error(`No tokens found for user ${userId}`);
            return res.sendStatus(404);
        }

        const user = await getUser(userId);
        if (!user) {
            console.warn(`User ${userId} not found in database`);
        }

        if (!tokens) {
            console.warn(
                `No tokens found for user ${userId}. Skipping Discord metadata removal.`
            );
        }

        const metadata = {
            is_dev: false,
            is_mod: false,
            is_ads: false,
            is_owner: false,
            is_contributor: false,
        };

        console.log(`📡 Removing metadata for ${userId}`);
        await discord.pushMetadata(userId, tokens, metadata);

        console.log(`🗑️ Attempting to remove user from database: ${userId}`);
        const result = await db.collection("users").deleteOne({
            userId: userId.toString(),
        });

        if (result.deletedCount === 0) {
            console.error(`❌ Failed to delete user ${userId} from database`);
        } else {
            console.log(`✅ User ${userId} successfully removed from database`);
        }

        // Storage'dan token'ları sil
        await storage.deleteDiscordTokens(userId);

        await updateAllowedIDs();
        res.sendStatus(204);
    } catch (e) {
        console.error("Error in /remove-metadata:", e, e.stack);
        res.sendStatus(500);
    }
});

await connectDB();
await updateAllowedIDs();

async function updateAllowedIDs() {
    const users = await getAllowedUsers();
    allowedIDs = {
        is_dev: [],
        is_mod: [],
        is_ads: [],
        is_owner: [],
        is_contributor: [],
    };

    users.forEach((user) => {
        if (user.is_dev) allowedIDs.is_dev.push(user.userId);
        if (user.is_mod) allowedIDs.is_mod.push(user.userId);
        if (user.is_ads) allowedIDs.is_ads.push(user.userId);
        if (user.is_owner) allowedIDs.is_owner.push(user.userId);
        if (user.is_contributor) allowedIDs.is_contributor.push(user.userId);
    });
}

app.post("/admin/add-user", async (req, res) => {
    const { userId, username, roles } = req.body;

    await updateUser(userId, {
        userId,
        username,
        is_dev: roles.includes("dev"),
        is_mod: roles.includes("mod"),
        is_ads: roles.includes("ads"),
        is_owner: roles.includes("owner"),
        is_contributor: roles.includes("contributor"),
    });

    await updateAllowedIDs();
    res.sendStatus(200);
});

app.post("/discord/commands/add-role", async (req, res) => {
    try {
        const { userId, role } = req.body;

        if (!userId || !role) {
            return res.status(400).json({
                error: "userId ve role parametreleri gerekli",
            });
        }

        const validRoles = ["dev", "mod", "ads", "owner", "contributor"];
        if (!validRoles.includes(role)) {
            return res.status(400).json({
                error: `Geçersiz rol. Geçerli roller: ${validRoles.join(", ")}`,
            });
        }

        const auth = req.headers.authorization;
        if (!auth || !auth.startsWith("Bot ")) {
            return res.status(401).json({
                error: "Yetkilendirme gerekli",
            });
        }

        const botToken = auth.split(" ")[1];
        try {
            const userData = await discord.getUserData(userId, botToken);
            if (!userData || !userData.username) {
                console.error(
                    `Invalid user data received for userId ${userId}:`,
                    userData
                );
                return res.status(404).json({
                    success: false,
                    error: "Discord kullanıcısı bulunamadı veya kullanıcı bilgileri eksik",
                });
            }

            await updateUser(userId, {
                userId,
                username: userData.username,
                is_dev: role === "dev",
                is_mod: role === "mod",
                is_ads: role === "ads",
                is_owner: role === "owner",
                is_contributor: role === "contributor",
            });

            await updateAllowedIDs();

            return res.status(200).json({
                success: true,
                message: `${userData.username} kullanıcısına ${role} rolü verildi`,
            });
        } catch (e) {
            console.error("Error in /discord/commands/add-role:", e);
            if (e.message.includes("Invalid response type")) {
                return res.status(502).json({
                    success: false,
                    error: "Discord API'den geçersiz yanıt alındı",
                });
            }
            return res.status(500).json({
                success: false,
                error: "Sunucu hatası oluştu: " + e.message,
            });
        }
    } catch (outerError) {
        console.error("Outer error in /discord/commands/add-role:", outerError);
        return res.status(500).json({
            success: false,
            error: "Beklenmeyen bir hata oluştu",
        });
    }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
});
