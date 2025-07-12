const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const app = express();
const PORT = 7860;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const USERS_FILE = 'users.json';
const CHARACTERS_FILE = 'characters.json';
const STORE_FILE = 'store.json';
const NEW_FILE = 'new.json';
const SPIN_FILE = 'spin.json';
const CHAT_FILE = 'chat.json';
const EVENT_FILE = 'event.json';
const EQUIP_FILE = 'equip.json';
const AUCTION_FILE = 'auction.json';
const SKILLS_FILE = 'skills.json';

const SPIN_COSTS = [100, 200, 300, 400, 500];
const ADMIN_USERNAME = 'Reiker';
const activeBattles = new Map();
const activeRooms = new Map();
const ACCEPT_TIMEOUT = 5 * 60 * 1000; // 5 minutes
const TURN_TIMEOUT = 60 * 1000; // 1 minute
const ROOM_TIMEOUT = 10 * 60 * 1000; // 10 minutes

function loadUsers() {
    if (!fs.existsSync(USERS_FILE)) return [];
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

function loadCharacters() {
    if (!fs.existsSync(CHARACTERS_FILE)) return [];
    return JSON.parse(fs.readFileSync(CHARACTERS_FILE, 'utf8'));
}

function loadStore() {
    if (!fs.existsSync(STORE_FILE)) return [];
    return JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
}

function loadNewCharacter() {
    if (!fs.existsSync(NEW_FILE)) return null;
    return JSON.parse(fs.readFileSync(NEW_FILE, 'utf8'));
}

function loadSpinProgress() {
    if (!fs.existsSync(SPIN_FILE)) return {};
    return JSON.parse(fs.readFileSync(SPIN_FILE, 'utf8'));
}

function loadChat() {
    if (!fs.existsSync(CHAT_FILE)) return [];
    return JSON.parse(fs.readFileSync(CHAT_FILE, 'utf8'));
}

function loadEvent() {
    if (!fs.existsSync(EVENT_FILE)) return { character: null, claims: [] };
    return JSON.parse(fs.readFileSync(EVENT_FILE, 'utf8'));
}

function loadEquip() {
    if (!fs.existsSync(EQUIP_FILE)) return {};
    return JSON.parse(fs.readFileSync(EQUIP_FILE, 'utf8'));
}

function loadAuction() {
    if (!fs.existsSync(AUCTION_FILE)) return {};
    return JSON.parse(fs.readFileSync(AUCTION_FILE, 'utf8'));
}

function loadSkills() {
    if (!fs.existsSync(SKILLS_FILE)) return { characters: [] };
    return JSON.parse(fs.readFileSync(SKILLS_FILE, 'utf8'));
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function saveStore(store) {
    fs.writeFileSync(STORE_FILE, JSON.stringify(store, null, 2));
}

function saveNewCharacter(character) {
    fs.writeFileSync(NEW_FILE, JSON.stringify(character, null, 2));
}

function saveSpinProgress(spinProgress) {
    fs.writeFileSync(SPIN_FILE, JSON.stringify(spinProgress, null, 2));
}

function saveChat(chat) {
    fs.writeFileSync(CHAT_FILE, JSON.stringify(chat, null, 2));
}

function saveEvent(event) {
    fs.writeFileSync(EVENT_FILE, JSON.stringify(event, null, 2));
}

function saveEquip(equip) {
    fs.writeFileSync(EQUIP_FILE, JSON.stringify(equip, null, 2));
}

function saveAuction(auction) {
    fs.writeFileSync(AUCTION_FILE, JSON.stringify(auction, null, 2));
}

function generateUserId(users) {
    let id;
    do {
        id = Math.floor(10000000 + Math.random() * 90000000).toString();
    } while (users.find(u => u.userId === id));
    return id;
}

function generateAuthToken() {
    return crypto.randomBytes(24).toString('hex');
}

function generateRoomCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function validateUsername(username) {
    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
    return usernameRegex.test(username);
}

function formatDuration(ms) {
    const totalSeconds = Math.floor(ms / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    return `${hours}h ${minutes}m`;
}

function isAdmin(req) {
    const token = req.headers.authorization;
    if (!token) return false;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    return user && user.username === ADMIN_USERNAME;
}

function updateRank(user) {
    const wins = user.wins || 0;
    if (wins >= 50) return `Diamond ${Math.floor((wins - 50) / 50) + 1}`;
    if (wins >= 20) return 'Platinum';
    if (wins >= 10) return 'Gold';
    if (wins >= 5) return 'Silver';
    return 'Bronze';
}

function startBattleTimeout(battle, type, res, users) {
    const timeout = type === 'accept' ? ACCEPT_TIMEOUT : TURN_TIMEOUT;
    const timeoutId = setTimeout(() => {
        if (!activeBattles.has(battle.id)) return;
        if (type === 'accept' && !battle.accepted) {
            battle.cancelled = true;
            activeBattles.delete(battle.id);
            res.json({ message: `Battle ${battle.id} timed out: Opponent did not accept within ${ACCEPT_TIMEOUT / 60000} minutes.` });
        } else if (type === 'turn') {
            const winnerId = battle.participants.find(id => id !== battle.currentTurn);
            activeBattles.delete(battle.id);
            endBattle(battle, winnerId, res, users, `Battle ended: ${battle.names[battle.currentTurn]} timed out on their turn.`);
        }
    }, timeout);
    battle[`${type}TimeoutId`] = timeoutId;
}

function clearBattleTimeout(battle, type) {
    if (battle[`${type}TimeoutId`]) {
        clearTimeout(battle[`${type}TimeoutId`]);
        delete battle[`${type}TimeoutId`];
    }
}

// Register endpoint
app.post('/register', async (req, res) => {
    const { username, password, bio } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required." });
    if (!validateUsername(username)) {
        return res.status(400).json({ error: "Username must be 3-20 characters, alphanumeric or underscores only." });
    }

    const users = loadUsers();
    if (users.find(u => u.username === username)) {
        return res.status(409).json({ error: "Username already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
        userId: generateUserId(users),
        authToken: generateAuthToken(),
        username,
        password: hashedPassword,
        bio: bio || "",
        coins: 400,
        diamonds: 0,
        level: 1,
        rank: "Bronze",
        wins: 0,
        losses: 0,
        verified: false,
        createdAt: new Date().toISOString(),
        likes: 0,
        characterIds: [22],
        characters: [],
        friends: []
    };

    users.push(user);
    saveUsers(users);

    res.json({ message: "Registered successfully", authToken: user.authToken, userId: user.userId });
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const users = loadUsers();
    const user = users.find(u => u.username === username);
    if (!user) return res.status(401).json({ error: "Invalid credentials." });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: "Invalid credentials." });

    res.json({ message: "Login successful", authToken: user.authToken, userId: user.userId });
});

// Protected route: Get user profile
app.get('/profile', (req, res) => {
    const token = req.headers.authorization;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });
    if (!validateUsername(user.username)) {
        return res.status(400).json({ error: "Invalid username format detected." });
    }

    res.json({
        username: user.username,
        verified: user.verified,
        bio: user.bio,
        diamonds: user.diamonds,
        coins: user.coins,
        level: user.level,
        rank: user.rank,
        wins: user.wins,
        losses: user.losses,
        likes: user.likes,
        characterIds: user.characterIds
    });
});

// Protected route: Get user characters
app.get('/characters', (req, res) => {
    const token = req.headers.authorization;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const characters = loadCharacters();
    const equip = loadEquip();
    const userCharacters = characters
        .filter(char => user.characterIds.includes(char.id))
        .map(char => ({
            id: char.id,
            name: char.name,
            power_rating: char.power_rating,
            level: equip[user.userId]?.[char.id]?.level || 1,
            equipped: equip[user.userId]?.[char.id]?.equipped || false
        }));

    res.json({ characters: userCharacters });
});

// Protected route: Purchase character
app.post('/purchase-character', (req, res) => {
    const token = req.headers.authorization;
    const { characterId } = req.body;

    if (!characterId) return res.status(400).json({ error: "Character ID is required." });

    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const store = loadStore();
    const storeItem = store.find(item => item.id === parseInt(characterId));
    if (!storeItem) return res.status(404).json({ error: "Character not found in store." });

    if (user.characterIds.includes(parseInt(characterId))) {
        return res.status(400).json({ error: "Character already owned." });
    }

    if (user.diamonds < storeItem.price) {
        return res.status(400).json({ error: "Insufficient diamonds." });
    }

    user.diamonds -= storeItem.price;
    user.characterIds.push(parseInt(characterId));
    saveUsers(users);

    res.json({ message: "Character purchased successfully", character: storeItem.name, remainingDiamonds: user.diamonds });
});

// Protected route: Spin for character
app.post('/spin', (req, res) => {
    const token = req.headers.authorization;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const characterData = loadNewCharacter();
    if (!characterData || !characterData.character_id || !characterData.character_name) {
        return res.status(400).json({ error: "Character data is missing or invalid." });
    }

    const characterId = characterData.character_id;
    const characterName = characterData.character_name;

    if (user.characterIds.includes(characterId)) {
        return res.status(400).json({ error: `You already own ${characterName} (ID: ${characterId})!` });
    }

    const spinProgress = loadSpinProgress();
    if (!spinProgress[user.userId]) spinProgress[user.userId] = 0;

    const currentSpin = spinProgress[user.userId];
    if (currentSpin >= SPIN_COSTS.length) {
        return res.status(400).json({ error: "You've reached the maximum number of spins!" });
    }

    const spinCost = SPIN_COSTS[currentSpin];
    if (user.coins < spinCost) {
        return res.status(400).json({ error: `Insufficient coins! You need ${spinCost} coins.` });
    }

    user.coins -= spinCost;
    const winChance = currentSpin === 0 ? 0.05 : 0.2;
    const wonCharacter = Math.random() < winChance || currentSpin === SPIN_COSTS.length - 1;

    if (wonCharacter) {
        user.characterIds.push(characterId);
        delete spinProgress[user.userId];
        saveUsers(users);
        saveSpinProgress(spinProgress);
        return res.json({
            message: `Congratulations! You won ${characterName} (ID: ${characterId})!`,
            remainingCoins: user.coins
        });
    } else {
        spinProgress[user.userId] += 1;
        const nextSpinCost = SPIN_COSTS[spinProgress[user.userId]] || "MAX";
        const spinsLeft = SPIN_COSTS.length - spinProgress[user.userId];
        saveUsers(users);
        saveSpinProgress(spinProgress);
        return res.json({
            message: `No luck this time! Next spin cost: ${nextSpinCost} coins. Spins left: ${spinsLeft}.`,
            remainingCoins: user.coins
        });
    }
});

// Leaderboard endpoint
app.get('/leaderboard', (req, res) => {
    const users = loadUsers();

    const topWins = users
        .sort((a, b) => b.wins - a.wins)
        .slice(0, 10)
        .map(user => ({ username: user.username, userId: user.userId, wins: user.wins, rank: user.rank }));

    const topCoins = users
        .sort((a, b) => b.coins - a.coins)
        .slice(0, 10)
        .map(user => ({ username: user.username, userId: user.userId, coins: user.coins, rank: user.rank }));

    res.json({
        topWins,
        topCoins
    });
});

// Admin route: Grant premium status
app.post('/admin/grant-premium', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized: Admin access required." });

    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: "User ID is required." });

    const users = loadUsers();
    const user = users.find(u => u.userId === userId);
    if (!user) return res.status(404).json({ error: "User not found." });

    if (user.verified) return res.status(400).json({ error: "User already has premium status." });

    user.verified = true;
    saveUsers(users);

    res.json({ message: `Premium status granted to ${user.username}.` });
});

// Admin route: Add coins or diamonds
app.post('/admin/add-currency', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized: Admin access required." });

    const { userId, coins, diamonds } = req.body;
    if (!userId || (coins === undefined && diamonds === undefined)) {
        return res.status(400).json({ error: "User ID and at least one of coins or diamonds are required." });
    }
    if ((coins !== undefined && (!Number.isInteger(coins) || coins < 0)) ||
        (diamonds !== undefined && (!Number.isInteger(diamonds) || diamonds < 0))) {
        return res.status(400).json({ error: "Coins and diamonds must be non-negative integers." });
    }

    const users = loadUsers();
    const user = users.find(u => u.userId === userId);
    if (!user) return res.status(404).json({ error: "User not found." });

    if (coins !== undefined) user.coins += coins;
    if (diamonds !== undefined) user.diamonds += diamonds;
    saveUsers(users);

    res.json({ message: `Added ${coins || 0} coins and ${diamonds || 0} diamonds to ${user.username}.` });
});

// Admin route: Grant character
app.post('/admin/grant-character', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized: Admin access required." });

    const { userId, characterId } = req.body;
    if (!userId || !characterId) return res.status(400).json({ error: "User ID and character ID are required." });

    const users = loadUsers();
    const user = users.find(u => u.userId === userId);
    if (!user) return res.status(404).json({ error: "User not found." });

    const characters = loadCharacters();
    const character = characters.find(c => c.id === parseInt(characterId));
    if (!character) return res.status(404).json({ error: "Character not found." });

    if (user.characterIds.includes(parseInt(characterId))) {
        return res.status(400).json({ error: `User already owns ${character.name} (ID: ${characterId}).` });
    }

    user.characterIds.push(parseInt(characterId));
    saveUsers(users);

    res.json({ message: `Character ${character.name} (ID: ${characterId}) granted to ${user.username}.` });
});

// Admin route: Grant item to verified player
app.post('/admin/grant-item', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized: Admin access required." });

    const { userId, itemType, value } = req.body;
    if (!userId || !itemType || value === undefined) {
        return res.status(400).json({ error: "User ID, item type, and value are required." });
    }
    if (!['coins', 'diamonds', 'character'].includes(itemType)) {
        return res.status(400).json({ error: "Item type must be 'coins', 'diamonds', or 'character'." });
    }

    const users = loadUsers();
    const user = users.find(u => u.userId === userId);
    if (!user) return res.status(404).json({ error: "User not found." });
    if (!user.verified) return res.status(400).json({ error: "User must be verified to receive items." });

    if (itemType === 'character') {
        const characterId = parseInt(value);
        const characters = loadCharacters();
        const character = characters.find(c => c.id === characterId);
        if (!character) return res.status(404).json({ error: "Character not found." });
        if (user.characterIds.includes(characterId)) {
            return res.status(400).json({ error: `User already owns ${character.name} (ID: ${characterId}).` });
        }
        user.characterIds.push(characterId);
        saveUsers(users);
        return res.json({ message: `Character ${character.name} (ID: ${characterId}) granted to ${user.username}.` });
    } else {
        if (!Number.isInteger(value) || value < 0) {
            return res.status(400).json({ error: `${itemType} must be a non-negative integer.` });
        }
        user[itemType] += value;
        saveUsers(users);
        return res.json({ message: `${value} ${itemType} granted to ${user.username}.` });
    }
});

// Admin route: Change spin character
app.post('/admin/change-spin-character', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized: Admin access required." });

    const { characterId, characterName } = req.body;
    if (!characterId || !characterName) {
        return res.status(400).json({ error: "Character ID and name are required." });
    }
    if (!Number.isInteger(characterId) || characterId <= 0) {
        return res.status(400).json({ error: "Character ID must be a positive integer." });
    }

    const characters = loadCharacters();
    const character = characters.find(c => c.id === parseInt(characterId));
    if (!character) return res.status(404).json({ error: "Character not found in characters.json." });

    const newCharacter = { character_id: parseInt(characterId), character_name: characterName };
    saveNewCharacter(newCharacter);

    res.json({ message: `Spin character changed to ${characterName} (ID: ${characterId}).` });
});

// Admin route: Add character to store
app.post('/admin/add-store-character', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized: Admin access required." });

    const { characterId, characterName, price } = req.body;
    if (!characterId || !characterName || !price) {
        return res.status(400).json({ error: "Character ID, name, and price are required." });
    }
    if (!Number.isInteger(characterId) || characterId <= 0 || !Number.isInteger(price) || price <= 0) {
        return res.status(400).json({ error: "Character ID and price must be positive integers." });
    }

    const characters = loadCharacters();
    const character = characters.find(c => c.id === parseInt(characterId));
    if (!character) return res.status(404).json({ error: "Character not found in characters.json." });

    const store = loadStore();
    if (store.find(item => item.id === parseInt(characterId))) {
        return res.status(400).json({ error: `Character ${characterName} (ID: ${characterId}) already in store.` });
    }

    store.push({ id: parseInt(characterId), name: characterName, price });
    saveStore(store);

    res.json({ message: `Character ${characterName} (ID: ${characterId}) added to store with price ${price}.` });
});

// Admin route: Ban user
app.post('/admin/ban-user', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized: Admin access required." });

    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: "User ID is required." });

    const users = loadUsers();
    const userIndex = users.findIndex(u => u.userId === userId);
    if (userIndex === -1) return res.status(404).json({ error: "User not found." });

    const bannedUser = users[userIndex];
    users.splice(userIndex, 1);
    saveUsers(users);

    const spinProgress = loadSpinProgress();
    delete spinProgress[userId];
    saveSpinProgress(spinProgress);

    res.json({ message: `User ${bannedUser.username} (ID: ${userId}) has been banned.` });
});

// Admin route: Reset all ranks
app.post('/admin/reset-ranks', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized: Admin access required." });

    const users = loadUsers();
    users.forEach(user => {
        user.rank = "Bronze";
    });
    saveUsers(users);

    res.json({ message: "All user ranks have been reset to Bronze." });
});

// Protected route: Add friend
app.post('/add-friend', (req, res) => {
    const token = req.headers.authorization;
    const { friendUserId } = req.body;

    if (!friendUserId) return res.status(400).json({ error: "Friend user ID is required." });

    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const friend = users.find(u => u.userId === friendUserId);
    if (!friend) return res.status(404).json({ error: "Friend user not found." });

    if (user.userId === friendUserId) return res.status(400).json({ error: "Cannot add yourself as a friend." });

    if (user.friends.includes(friendUserId)) {
        return res.status(400).json({ error: `User ${friend.username} is already your friend.` });
    }

    user.friends.push(friendUserId);
    saveUsers(users);

    res.json({ message: `Friend ${friend.username} (ID: ${friendUserId}) added successfully.` });
});

// Protected route: Get friends
app.get('/friends', (req, res) => {
    const token = req.headers.authorization;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const friends = users
        .filter(u => user.friends.includes(u.userId))
        .map(u => ({ userId: u.userId, username: u.username, verified: u.verified }));

    res.json({ friends });
});

// Protected route: World chat - Post message
app.post('/chat', (req, res) => {
    const token = req.headers.authorization;
    const { message } = req.body;

    if (!message || message.trim().length === 0) {
        return res.status(400).json({ error: "Message is required and cannot be empty." });
    }
    if (message.length > 500) {
        return res.status(400).json({ error: "Message cannot exceed 500 characters." });
    }

    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const chat = loadChat();
    chat.push({
        userId: user.userId,
        username: user.username,
        message: message.trim(),
        timestamp: new Date().toISOString()
    });

    if (chat.length > 50) chat.splice(0, chat.length - 50);
    saveChat(chat);

    res.json({ message: "Message sent successfully." });
});

// Protected route: World chat - Get messages
app.get('/chat', (req, res) => {
    const token = req.headers.authorization;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const chat = loadChat();
    res.json({ messages: chat });
});

// Protected route: Search users
app.get('/search-users', (req, res) => {
    const token = req.headers.authorization;
    const { username, userId } = req.query;

    if (!username && !userId) {
        return res.status(400).json({ error: "Username or user ID is required." });
    }

    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    let results = [];
    if (userId) {
        const found = users.find(u => u.userId === userId);
        if (found) results.push({ userId: found.userId, username: found.username, verified: found.verified });
    } else if (username) {
        const found = users.find(u => u.username.toLowerCase() === username.toLowerCase());
        if (found) results.push({ userId: found.userId, username: found.username, verified: found.verified });
    }

    res.json({ users: results });
});

// Protected route: Get store
app.get('/store', (req, res) => {
    const token = req.headers.authorization;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const store = loadStore();
    res.json({ store });
});

// Protected route: Get event
app.get('/event', (req, res) => {
    const token = req.headers.authorization;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const event = loadEvent();
    res.json({
        character: event.character,
        claimed: event.claims.includes(user.userId)
    });
});

// Admin route: Set event character
app.post('/admin/set-event-character', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized: Admin access required." });

    const { characterId, characterName } = req.body;
    if (!characterId || !characterName) {
        return res.status(400).json({ error: "Character ID and name are required." });
    }
    if (!Number.isInteger(characterId) || characterId <= 0) {
        return res.status(400).json({ error: "Character ID must be a positive integer." });
    }

    const characters = loadCharacters();
    const character = characters.find(c => c.id === parseInt(characterId));
    if (!character) return res.status(404).json({ error: "Character not found in characters.json." });

    const event = { character: { id: parseInt(characterId), name: characterName }, claims: [] };
    saveEvent(event);

    res.json({ message: `Event character set to ${characterName} (ID: ${characterId}).` });
});

// Protected route: Claim event character
app.post('/claim-event-character', (req, res) => {
    const token = req.headers.authorization;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const event = loadEvent();
    if (!event.character) return res.status(400).json({ error: "No active event character." });

    if (event.claims.includes(user.userId)) {
        return res.status(400).json({ error: "You have already claimed the event character." });
    }

    if (user.characterIds.includes(event.character.id)) {
        return res.status(400).json({ error: `You already own ${event.character.name} (ID: ${event.character.id}).` });
    }

    user.characterIds.push(event.character.id);
    event.claims.push(user.userId);
    saveUsers(users);
    saveEvent(event);

    res.json({ message: `Successfully claimed event character ${event.character.name} (ID: ${event.character.id}).` });
});

// Route for serving login.html on "/"
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Protected route: Get character upgrades
app.get('/upgrade-character', (req, res) => {
    const token = req.headers.authorization;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    if (!user.characterIds || user.characterIds.length === 0) {
        return res.status(400).json({ error: "You do not own any characters." });
    }

    const characters = loadCharacters();
    const equip = loadEquip();
    const userCharacters = user.characterIds.map(characterId => {
        const character = characters.find(c => c.id === parseInt(characterId));
        if (!character) return null;
        const level = equip[user.userId]?.[characterId]?.level || 1;
        const equipped = equip[user.userId]?.[characterId]?.equipped || false;
        const upgradeCost = Math.floor(100 + 50 * level ** 1.5);
        return {
            characterId,
            name: character.name,
            level,
            equipped,
            nextLevelCost: upgradeCost
        };
    }).filter(char => char !== null);

    res.json({ characters: userCharacters });
});

// Protected route: Upgrade character
app.post('/upgrade-character', (req, res) => {
    const token = req.headers.authorization;
    const { characterId } = req.body;

    if (!characterId) return res.status(400).json({ error: "Character ID is required." });

    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    if (!user.characterIds.includes(parseInt(characterId))) {
        return res.status(400).json({ error: "You do not own this character." });
    }

    const characters = loadCharacters();
    const character = characters.find(c => c.id === parseInt(characterId));
    if (!character) return res.status(404).json({ error: "Character not found." });

    const equip = loadEquip();
    if (!equip[user.userId]) equip[user.userId] = {};
    if (!equip[user.userId][characterId]) equip[user.userId][characterId] = { level: 1, equipped: false };

    const level = equip[user.userId][characterId].level;
    const upgradeCost = Math.floor(100 + 50 * level ** 1.5);

    if (user.coins < upgradeCost) {
        return res.status(400).json({ error: `You need ${upgradeCost} coins to upgrade ${character.name}, but you only have ${user.coins} coins.` });
    }

    user.coins -= upgradeCost;
    equip[user.userId][characterId].level += 1;
    saveUsers(users);
    saveEquip(equip);

    res.json({ message: `${character.name} upgraded to Level ${equip[user.userId][characterId].level}!`, remainingCoins: user.coins });
});

// Protected route: Equip character
app.post('/equip-character', (req, res) => {
    const token = req.headers.authorization;
    const { characterId } = req.body;

    if (!characterId) return res.status(400).json({ error: "Character ID is required." });

    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    if (!user.characterIds.includes(parseInt(characterId))) {
        return res.status(400).json({ error: "You do not own this character." });
    }

    const characters = loadCharacters();
    const character = characters.find(c => c.id === parseInt(characterId));
    if (!character) return res.status(404).json({ error: "Character not found." });

    const equip = loadEquip();
    if (!equip[user.userId]) equip[user.userId] = {};

    Object.keys(equip[user.userId]).forEach(cid => {
        equip[user.userId][cid].equipped = false;
    });

    if (!equip[user.userId][characterId]) equip[user.userId][characterId] = { level: 1, equipped: false };
    equip[user.userId][characterId].equipped = true;

    saveEquip(equip);

    res.json({ message: `${character.name} (ID: ${characterId}) equipped successfully.` });
});

// Admin route: Start auction
app.post('/admin/start-auction', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized: Admin access required." });

    const { characterId, startPrice } = req.body;
    if (!characterId || startPrice === undefined) {
        return res.status(400).json({ error: "Character ID and start price are required." });
    }
    if (!Number.isInteger(characterId) || characterId <= 0 || !Number.isFinite(startPrice) || startPrice <= 0) {
        return res.status(400).json({ error: "Character ID must be a positive integer and start price must be a positive number." });
    }

    const auction = loadAuction();
    if (auction.active) {
        return res.status(400).json({ error: "An auction is already active." });
    }

    const characters = loadCharacters();
    const character = characters.find(c => c.id === parseInt(characterId));
    if (!character) return res.status(404).json({ error: "Character not found." });

    const now = Date.now();
    const newAuction = {
        active: true,
        characterId: parseInt(characterId),
        startPrice,
        startedAt: now,
        endAt: now + 24 * 60 * 60 * 1000,
        bids: []
    };

    saveAuction(newAuction);

    res.json({ message: `Auction started for ${character.name} (ID: ${characterId}) with start price ${startPrice} coins.` });
});

// Protected route: Place bid
app.post('/bid', (req, res) => {
    const token = req.headers.authorization;
    const { amount } = req.body;

    if (amount === undefined || !Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({ error: "Valid bid amount is required." });
    }

    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const auction = loadAuction();
    if (!auction.active) return res.status(400).json({ error: "No active auction." });
    if (Date.now() > auction.endAt) return res.status(400).json({ error: "Auction already ended." });

    const character = loadCharacters().find(c => c.id === auction.characterId);
    if (!character) return res.status(404).json({ error: "Character not found." });

    if (user.characterIds.includes(character.id)) {
        return res.status(400).json({ error: "You already own this character and cannot bid on it." });
    }

    if (amount < auction.startPrice) {
        return res.status(400).json({ error: `Your bid must be at least the starting price of ${auction.startPrice} coins.` });
    }

    const highestBid = auction.bids.length > 0 ? auction.bids[auction.bids.length - 1] : null;
    if (highestBid && amount <= highestBid.amount) {
        return res.status(400).json({ error: `Your bid must be higher than the current highest bid of ${highestBid.amount} coins.` });
    }

    const existingBidIndex = auction.bids.findIndex(b => b.userId === user.userId);
    const existingBidAmount = existingBidIndex !== -1 ? auction.bids[existingBidIndex].amount : 0;
    const availableBalance = user.coins + existingBidAmount;

    if (availableBalance < amount) {
        return res.status(400).json({ error: "Insufficient balance." });
    }

    if (existingBidIndex !== -1) {
        user.coins += existingBidAmount;
        auction.bids.splice(existingBidIndex, 1);
    }

    user.coins -= amount;
    auction.bids.push({ userId: user.userId, amount });

    saveUsers(users);
    saveAuction(auction);

    res.json({ message: `${user.username} placed a bid of ${amount} coins!`, remainingCoins: user.coins });
});

// Protected route: View bids
app.get('/bids', (req, res) => {
    const token = req.headers.authorization;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const auction = loadAuction();
    if (!auction.active) return res.status(400).json({ error: "No active auction." });

    const timeLeft = auction.endAt - Date.now();
    const character = loadCharacters().find(c => c.id === auction.characterId);
    const bidsList = auction.bids.map(bid => {
        const bidder = users.find(u => u.userId === bid.userId);
        const name = bidder ? bidder.username : "Unknown";
        return { username: name, amount: bid.amount };
    });

    const highest = auction.bids.length > 0 ? auction.bids[auction.bids.length - 1] : null;
    const leaderName = highest && users.find(u => u.userId === highest.userId) ? users.find(u => u.userId === highest.userId).username : "None";

    res.json({
        character: character ? { id: character.id, name: character.name } : null,
        startPrice: auction.startPrice,
        timeLeft: formatDuration(timeLeft),
        currentLeader: leaderName,
        bids: bidsList
    });
});

// Protected route: Settle auction
app.post('/settle-auction', (req, res) => {
    const token = req.headers.authorization;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const auction = loadAuction();
    if (!auction.active || Date.now() < auction.endAt) {
        return res.status(400).json({ error: "No active auction or auction has not ended." });
    }

    const character = loadCharacters().find(c => c.id === auction.characterId);
    if (!character) return res.status(404).json({ error: "Character not found." });

    if (auction.bids.length === 0) {
        saveAuction({});
        return res.json({ message: "Auction ended with no bids." });
    }

    const highest = auction.bids[auction.bids.length - 1];
    const winner = users.find(u => u.userId === highest.userId);
    const winnerAmount = highest.amount;

    for (let i = 0; i < auction.bids.length - 1; i++) {
        const bid = auction.bids[i];
        const bidder = users.find(u => u.userId === bid.userId);
        if (bidder) {
            bidder.coins += bid.amount;
        }
    }

    if (!winner.characterIds.includes(character.id)) {
        winner.characterIds.push(character.id);
    }

    saveUsers(users);
    saveAuction({});

    res.json({ message: `${winner.username} won the auction for ${character.name} (ID: ${character.id}) with ${winnerAmount} coins!` });
});

// Protected route: Create private battle room
app.post('/battle/room/create', (req, res) => {
    const token = req.headers.authorization;
    const { amount } = req.body;

    if (!Number.isInteger(amount) || amount < 1) {
        return res.status(400).json({ error: "Amount must be a positive integer." });
    }

    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    if (Array.from(activeBattles.values()).some(b => b.participants.includes(user.userId))) {
        return res.status(400).json({ error: "You are already in a battle." });
    }

    if (user.coins < amount) {
        return res.status(400).json({ error: "You don't have enough coins." });
    }

    const equip = loadEquip();
    const userEquip = equip[user.userId] || {};
    const userCharId = Object.keys(userEquip).find(id => userEquip[id]?.equipped);
    if (!userCharId) return res.status(400).json({ error: "You need an equipped character." });

    const roomCode = generateRoomCode();
    const room = {
        roomCode,
        creatorId: user.userId,
        creatorName: user.username,
        amount,
        opponentId: null,
        opponentName: null,
        createdAt: Date.now(),
        started: false
    };

    activeRooms.set(roomCode, room);

    setTimeout(() => {
        if (activeRooms.has(roomCode) && !room.started) {
            activeRooms.delete(roomCode);
        }
    }, ROOM_TIMEOUT);

    res.json({
        message: `Private room created by ${user.username} for ${amount} coins.`,
        roomCode,
        amount
    });
});

// Protected route: Join private battle room
app.post('/battle/room/join', (req, res) => {
    const token = req.headers.authorization;
    const { roomCode } = req.body;

    if (!roomCode) return res.status(400).json({ error: "Room code is required." });

    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const room = activeRooms.get(roomCode);
    if (!room) return res.status(404).json({ error: "Room not found." });
    if (room.started) return res.status(400).json({ error: "Room battle has already started." });
    if (room.creatorId === user.userId) return res.status(400).json({ error: "You cannot join your own room." });
    if (room.opponentId) return res.status(400).json({ error: "Room is already full." });

    if (Array.from(activeBattles.values()).some(b => b.participants.includes(user.userId))) {
        return res.status(400).json({ error: "You are already in a battle." });
    }

    if (user.coins < room.amount) {
        return res.status(400).json({ error: "You don't have enough coins." });
    }

    const equip = loadEquip();
    const userEquip = equip[user.userId] || {};
    const userCharId = Object.keys(userEquip).find(id => userEquip[id]?.equipped);
    if (!userCharId) return res.status(400).json({ error: "You need an equipped character." });

    room.opponentId = user.userId;
    room.opponentName = user.username;

    res.json({
        message: `${user.username} joined the room created by ${room.creatorName} for ${room.amount} coins.`,
        roomCode,
        creator: room.creatorName,
        amount
    });
});

// Protected route: Start private room battle
app.post('/battle/room/start', (req, res) => {
    const token = req.headers.authorization;
    const { roomCode } = req.body;

    if (!roomCode) return res.status(400).json({ error: "Room code is required." });

    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const room = activeRooms.get(roomCode);
    if (!room) return res.status(404).json({ error: "Room not found." });
    if (room.creatorId !== user.userId) return res.status(403).json({ error: "Only the room creator can start the battle." });
    if (!room.opponentId) return res.status(400).json({ error: "Room needs an opponent to start." });
    if (room.started) return res.status(400).json({ error: "Battle already started." });

    const challenger = users.find(u => u.userId === room.creatorId);
    const opponent = users.find(u => u.userId === room.opponentId);

    const equip = loadEquip();
    const challengerEquip = equip[challenger.userId] || {};
    const opponentEquip = equip[opponent.userId] || {};

    const challengerCharId = Object.keys(challengerEquip).find(id => challengerEquip[id]?.equipped);
    const opponentCharId = Object.keys(opponentEquip).find(id => opponentEquip[id]?.equipped);

    if (!challengerCharId || !opponentCharId) {
        return res.status(400).json({ error: "Both players need an equipped character." });
    }

    const skills = loadSkills();
    const challengerCharacter = skills.characters.find(c => c.id === parseInt(challengerCharId));
    const opponentCharacter = skills.characters.find(c => c.id === parseInt(opponentCharId));

    if (!challengerCharacter || !opponentCharacter) {
        return res.status(404).json({ error: "Character data missing." });
    }

    const battleId = `${challenger.userId}_${opponent.userId}_${Date.now()}`;
    const battle = {
        id: battleId,
        amount: room.amount,
        participants: [challenger.userId, opponent.userId],
        names: {
            [challenger.userId]: challenger.username,
            [opponent.userId]: opponent.username
        },
        userIds: {
            [challenger.userId]: challenger.userId,
            [opponent.userId]: opponent.userId
        },
        originalCharacters: {
            [challenger.userId]: {
                ...challengerCharacter,
                level: challengerEquip[challengerCharId]?.level || 1
            },
            [opponent.userId]: {
                ...opponentCharacter,
                level: opponentEquip[opponentCharId]?.level || 1
            }
        },
        characters: {
            [challenger.userId]: {
                ...challengerCharacter,
                currentHP: Math.floor(challengerCharacter.hp * 0.85),
                level: challengerEquip[challengerCharId]?.level || 1
            },
            [opponent.userId]: {
                ...opponentCharacter,
                currentHP: Math.floor(opponentCharacter.hp * 0.85),
                level: opponentEquip[opponentCharId]?.level || 1
            }
        },
        currentRound: 1,
        maxRounds: 3,
        roundResults: [],
        roundsWon: {
            [challenger.userId]: 0,
            [opponent.userId]: 0
        },
        battleStats: {
            [challenger.userId]: {
                totalDamageDealt: 0,
                totalDamageTaken: 0,
                totalTurns: 0,
                roundsWon: 0,
                hpLostPercentage: 0
            },
            [opponent.userId]: {
                totalDamageDealt: 0,
                totalDamageTaken: 0,
                totalTurns: 0,
                roundsWon: 0,
                hpLostPercentage: 0
            }
        },
        isQuickRound: false,
        currentTurn: challenger.userId,
        turnCount: 0,
        accepted: true,
        cancelled: false
    };

    room.started = true;
    activeBattles.set(battleId, battle);
    activeRooms.delete(roomCode);

    challenger.coins -= battle.amount;
    opponent.coins -= battle.amount;
    saveUsers(users);

    startBattleTimeout(battle, 'turn', res, users);

    res.json({
        message: `Battle started in room ${roomCode} between ${challenger.username} and ${opponent.username}!`,
        battleId,
        currentTurn: battle.names[battle.currentTurn],
        skills: battle.characters[battle.currentTurn].skills.map((s, i) => ({ letter: String.fromCharCode(65 + i), name: s.name }))
    });
});

// Protected route: Get available rooms
app.get('/battle/rooms', (req, res) => {
    const token = req.headers.authorization;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const rooms = Array.from(activeRooms.values())
        .filter(r => !r.started && !r.opponentId)
        .map(r => ({
            roomCode: r.roomCode,
            creatorName: r.creatorName,
            amount: r.amount,
            createdAt: r.createdAt
        }));

    res.json({ rooms });
});

// Protected route: Matchmake random opponent
app.post('/battle/matchmake', (req, res) => {
    const token = req.headers.authorization;
    const { amount } = req.body;

    if (!Number.isInteger(amount) || amount < 1) {
        return res.status(400).json({ error: "Amount must be a positive integer." });
    }

    const users = loadUsers();
    const challenger = users.find(u => u.authToken === token);
    if (!challenger) return res.status(403).json({ error: "Invalid or missing authToken." });

    if (Array.from(activeBattles.values()).some(b => b.participants.includes(challenger.userId))) {
        return res.status(400).json({ error: "You are already in a battle." });
    }

    if (challenger.coins < amount) {
        return res.status(400).json({ error: "You don't have enough coins." });
    }

    const equip = loadEquip();
    const challengerEquip = equip[challenger.userId] || {};
    const challengerCharId = Object.keys(challengerEquip).find(id => challengerEquip[id]?.equipped);
    if (!challengerCharId) return res.status(400).json({ error: "You need an equipped character." });

    const eligibleOpponents = users.filter(u =>
        u.userId !== challenger.userId &&
        !Array.from(activeBattles.values()).some(b => b.participants.includes(u.userId)) &&
        u.coins >= amount &&
        equip[u.userId] && Object.keys(equip[u.userId]).some(id => equip[u.userId][id]?.equipped)
    );

    if (eligibleOpponents.length === 0) {
        return res.status(400).json({ error: "No eligible opponents available." });
    }

    const opponent = eligibleOpponents[Math.floor(Math.random() * eligibleOpponents.length)];
    const opponentEquip = equip[opponent.userId] || {};
    const opponentCharId = Object.keys(opponentEquip).find(id => opponentEquip[id]?.equipped);

    const skills = loadSkills();
    const challengerCharacter = skills.characters.find(c => c.id === parseInt(challengerCharId));
    const opponentCharacter = skills.characters.find(c => c.id === parseInt(opponentCharId));

    if (!challengerCharacter || !opponentCharacter) {
        return res.status(404).json({ error: "Character data missing." });
    }

    const battleId = `${challenger.userId}_${opponent.userId}_${Date.now()}`;
    const battle = {
        id: battleId,
        amount,
        participants: [challenger.userId, opponent.userId],
        names: {
            [challenger.userId]: challenger.username,
            [opponent.userId]: opponent.username
        },
        userIds: {
            [challenger.userId]: challenger.userId,
            [opponent.userId]: opponent.userId
        },
        originalCharacters: {
            [challenger.userId]: {
                ...challengerCharacter,
                level: challengerEquip[challengerCharId]?.level || 1
            },
            [opponent.userId]: {
                ...opponentCharacter,
                level: opponentEquip[opponentCharId]?.level || 1
            }
        },
        characters: {
            [challenger.userId]: {
                ...challengerCharacter,
                currentHP: Math.floor(challengerCharacter.hp * 0.85),
                level: challengerEquip[challengerCharId]?.level || 1
            },
            [opponent.userId]: {
                ...opponentCharacter,
                currentHP: Math.floor(opponentCharacter.hp * 0.85),
                level: opponentEquip[opponentCharId]?.level || 1
            }
        },
        currentRound: 1,
        maxRounds: 3,
        roundResults: [],
        roundsWon: {
            [challenger.userId]: 0,
            [opponent.userId]: 0
        },
        battleStats: {
            [challenger.userId]: {
                totalDamageDealt: 0,
                totalDamageTaken: 0,
                totalTurns: 0,
                roundsWon: 0,
                hpLostPercentage: 0
            },
            [opponent.userId]: {
                totalDamageDealt: 0,
                totalDamageTaken: 0,
                totalTurns: 0,
                roundsWon: 0,
                hpLostPercentage: 0
            }
        },
        isQuickRound: false,
        currentTurn: challenger.userId,
        turnCount: 0,
        accepted: false,
        cancelled: false
    };

    activeBattles.set(battleId, battle);
    startBattleTimeout(battle, 'accept', res, users);

    res.json({
        message: `${challenger.username} challenged ${opponent.username} to a battle for ${amount} coins!`,
        battleId,
        format: "Best of 3 rounds",
        hpStatus: "Reduced by 15% for rounds 1-2",
        opponentAction: `${opponent.username} must accept the challenge.`
    });
});

// Protected route: Get active battles
app.get('/battle/active', (req, res) => {
    const token = req.headers.authorization;
    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const battles = Array.from(activeBattles.values())
        .filter(b => b.participants.includes(user.userId))
        .map(b => ({
            battleId: b.id,
            opponent: b.names[b.participants.find(id => id !== user.userId)],
            amount: b.amount,
            accepted: b.accepted,
            currentRound: b.currentRound,
            currentTurn: b.names[b.currentTurn],
            yourTurn: b.currentTurn === user.userId,
            skills: b.accepted && b.currentTurn === user.userId ? b.characters[user.userId].skills.map((s, i) => ({ letter: String.fromCharCode(65 + i), name: s.name })) : []
        }));

    res.json({ battles });
});

// Protected route: Challenge battle
app.post('/battle/challenge', (req, res) => {
    const token = req.headers.authorization;
    const { opponentUserId, amount } = req.body;

    if (!opponentUserId || !Number.isInteger(amount) || amount < 1) {
        return res.status(400).json({ error: "Opponent user ID and amount (minimum 1 coin) are required." });
    }

    const users = loadUsers();
    const challenger = users.find(u => u.authToken === token);
    if (!challenger) return res.status(403).json({ error: "Invalid or missing authToken." });

    const opponent = users.find(u => u.userId === opponentUserId);
    if (!opponent) return res.status(404).json({ error: "Opponent user not found." });

    if (challenger.userId === opponentUserId) {
        return res.status(400).json({ error: "You cannot battle yourself." });
    }

    if (Array.from(activeBattles.values()).some(b => b.participants.includes(challenger.userId) || b.participants.includes(opponentUserId))) {
        return res.status(400).json({ error: "One or both users are already in a battle." });
    }

    if (challenger.coins < amount) {
        return res.status(400).json({ error: "You don't have enough coins." });
    }

    if (opponent.coins < amount) {
        return res.status(400).json({ error: `${opponent.username} doesn't have enough coins.` });
    }

    const equip = loadEquip();
    const challengerEquip = equip[challenger.userId] || {};
    const opponentEquip = equip[opponent.userId] || {};

    const challengerCharId = Object.keys(challengerEquip).find(id => challengerEquip[id]?.equipped);
    const opponentCharId = Object.keys(opponentEquip).find(id => opponentEquip[id]?.equipped);

    if (!challengerCharId || !opponentCharId) {
        return res.status(400).json({ error: "Both players need an equipped character." });
    }

    const skills = loadSkills();
    const challengerCharacter = skills.characters.find(c => c.id === parseInt(challengerCharId));
    const opponentCharacter = skills.characters.find(c => c.id === parseInt(opponentCharId));

    if (!challengerCharacter || !opponentCharacter) {
        return res.status(404).json({ error: "Character data missing." });
    }

    const battleId = `${challenger.userId}_${opponent.userId}_${Date.now()}`;
    const battle = {
        id: battleId,
        amount,
        participants: [challenger.userId, opponent.userId],
        names: {
            [challenger.userId]: challenger.username,
            [opponent.userId]: opponent.username
        },
        userIds: {
            [challenger.userId]: challenger.userId,
            [opponent.userId]: opponent.userId
        },
        originalCharacters: {
            [challenger.userId]: {
                ...challengerCharacter,
                level: challengerEquip[challengerCharId]?.level || 1
            },
            [opponent.userId]: {
                ...opponentCharacter,
                level: opponentEquip[opponentCharId]?.level || 1
            }
        },
        characters: {
            [challenger.userId]: {
                ...challengerCharacter,
                currentHP: Math.floor(challengerCharacter.hp * 0.85),
                level: challengerEquip[challengerCharId]?.level || 1
            },
            [opponent.userId]: {
                ...opponentCharacter,
                currentHP: Math.floor(opponentCharacter.hp * 0.85),
                level: opponentEquip[opponentCharId]?.level || 1
            }
        },
        currentRound: 1,
        maxRounds: 3,
        roundResults: [],
        roundsWon: {
            [challenger.userId]: 0,
            [opponent.userId]: 0
        },
        battleStats: {
            [challenger.userId]: {
                totalDamageDealt: 0,
                totalDamageTaken: 0,
                totalTurns: 0,
                roundsWon: 0,
                hpLostPercentage: 0
            },
            [opponent.userId]: {
                totalDamageDealt: 0,
                totalDamageTaken: 0,
                totalTurns: 0,
                roundsWon: 0,
                hpLostPercentage: 0
            }
        },
        isQuickRound: false,
        currentTurn: challenger.userId,
        turnCount: 0,
        accepted: false,
        cancelled: false
    };

    activeBattles.set(battleId, battle);
    startBattleTimeout(battle, 'accept', res, users);

    res.json({
        message: `${challenger.username} challenged ${opponent.username} to a battle for ${amount} coins!`,
        battleId,
        format: "Best of 3 rounds",
        hpStatus: "Reduced by 15% for rounds 1-2",
        opponentAction: `${opponent.username} must accept the challenge.`
    });
});

// Protected route: Accept battle
app.post('/battle/accept', (req, res) => {
    const token = req.headers.authorization;
    const { battleId } = req.body;

    if (!battleId) return res.status(400).json({ error: "Battle ID is required." });

    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const battle = activeBattles.get(battleId);
    if (!battle) return res.status(404).json({ error: "Battle not found." });
    if (battle.accepted || battle.cancelled) return res.status(400).json({ error: "Battle already accepted or cancelled." });
    if (battle.participants[1] !== user.userId) return res.status(403).json({ error: "You are not the opponent in this battle." });

    battle.accepted = true;
    const challenger = users.find(u => u.userId === battle.participants[0]);
    const opponent = users.find(u => u.userId === battle.participants[1]);

    challenger.coins -= battle.amount;
    opponent.coins -= battle.amount;
    saveUsers(users);

    clearBattleTimeout(battle, 'accept');
    startBattleTimeout(battle, 'turn', res, users);

    res.json({
        message: `${user.username} accepted the battle! Round 1 begins.`,
        battleId,
        currentTurn: battle.names[battle.currentTurn],
        skills: battle.characters[user.userId].skills.map((s, i) => ({ letter: String.fromCharCode(65 + i), name: s.name }))
    });
});

// Protected route: Attack in battle
app.post('/battle/attack', (req, res) => {
    const token = req.headers.authorization;
    const { battleId, skillLetter } = req.body;

    if (!battleId || !skillLetter) return res.status(400).json({ error: "Battle ID and skill letter are required." });

    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const battle = activeBattles.get(battleId);
    if (!battle || !battle.accepted || battle.cancelled || battle.currentTurn !== user.userId) {
        return res.status(400).json({ error: "Invalid battle, not your turn, or battle not active." });
    }

    const letters = ['A', 'B', 'C', 'D', 'E'];
    const skillIndex = letters.indexOf(skillLetter.toUpperCase());
    if (skillIndex === -1) return res.status(400).json({ error: "Invalid skill letter (must be A-E)." });

    const player = user.userId;
    const opponent = battle.participants.find(id => id !== player);
    const playerChar = battle.characters[player];
    const opponentChar = battle.characters[opponent];

    const skill = playerChar.skills[skillIndex];
    if (!skill) return res.status(400).json({ error: "Skill not found." });

    const calculateDamage = () => {
        let baseDamage = skill.power_rating * 10;
        if (battle.isQuickRound) baseDamage *= 2;
        const levelBonus = (playerChar.level - 1) * 5;
        const randomVariation = Math.floor(baseDamage * 0.05 * Math.random());
        const levelDiff = Math.min(50, Math.max(-50, playerChar.level - opponentChar.level));
        const levelDiffMultiplier = 1 + (levelDiff * 0.001);
        let totalDamage = Math.floor((baseDamage + levelBonus + randomVariation) * levelDiffMultiplier);
        return Math.max(1, totalDamage);
    };

    const levelDifference = Math.max(0, playerChar.level - opponentChar.level);
    let critChance = 0.15 + (levelDifference * 0.001);
    if (battle.isQuickRound) critChance += 0.1;
    const isCritical = Math.random() < critChance;

    let damage = calculateDamage();
    if (isCritical) damage = Math.floor(damage * 1.5);

    battle.battleStats[player].totalDamageDealt += damage;
    battle.battleStats[opponent].totalDamageTaken += damage;
    battle.battleStats[player].totalTurns++;
    battle.turnCount++;

    opponentChar.currentHP = Math.max(0, opponentChar.currentHP - damage);

    const playerOriginalChar = battle.originalCharacters[player];
    const opponentOriginalChar = battle.originalCharacters[opponent];
    const playerMaxHP = battle.currentRound <= 2 ? Math.floor(playerOriginalChar.hp * 0.85) : playerOriginalChar.hp;
    const opponentMaxHP = battle.currentRound <= 2 ? Math.floor(opponentOriginalChar.hp * 0.85) : opponentOriginalChar.hp;

    clearBattleTimeout(battle, 'turn');

    if (opponentChar.currentHP <= 0) {
        battle.battleStats[player].roundsWon++;
        battle.roundResults.push({
            round: battle.currentRound,
            winner: player,
            turns: battle.turnCount,
            isQuickRound: battle.isQuickRound
        });

        if (battle.roundsWon[player] >= 2) {
            activeBattles.delete(battle.id);
            endBattle(battle, player, res, users);
            return;
        } else if (battle.currentRound >= 3) {
            const finalWinner = determineFinalWinner(battle);
            activeBattles.delete(battle.id);
            endBattle(battle, finalWinner, res, users);
            return;
        } else {
            battle.currentRound++;
            if (battle.currentRound === 3 && battle.roundsWon[battle.participants[0]] === 1 && battle.roundsWon[battle.participants[1]] === 1) {
                battle.isQuickRound = true;
            }
            startNewRound(battle, res, users);
            return;
        }
    }

    battle.currentTurn = opponent;
    startBattleTimeout(battle, 'turn', res, users);

    res.json({
        message: `${battle.names[player]}'s ${playerChar.name} used ${skill.name} and dealt ${damage} damage${isCritical ? " (CRITICAL HIT)" : ""}!`,
        opponentHP: `${opponentChar.currentHP}/${opponentMaxHP}`,
        playerHP: `${playerChar.currentHP}/${playerMaxHP}`,
        currentTurn: battle.names[opponent],
        skills: battle.characters[opponent].skills.map((s, i) => ({ letter: String.fromCharCode(65 + i), name: s.name }))
    });
});

// Protected route: Leave battle
app.post('/battle/leave', (req, res) => {
    const token = req.headers.authorization;
    const { battleId } = req.body;

    if (!battleId) return res.status(400).json({ error: "Battle ID is required." });

    const users = loadUsers();
    const user = users.find(u => u.authToken === token);
    if (!user) return res.status(403).json({ error: "Invalid or missing authToken." });

    const battle = activeBattles.get(battleId);
    if (!battle || battle.accepted) {
        return res.status(400).json({ error: "No pending battle found or battle already started." });
    }

    battle.cancelled = true;
    clearBattleTimeout(battle, 'accept');
    activeBattles.delete(battle.id);

    res.json({ message: `${user.username} has left the battle. Challenge cancelled.` });
});

function startNewRound(battle, res, users) {
    battle.participants.forEach(id => {
        const originalChar = battle.originalCharacters[id];
        let roundHP = battle.currentRound <= 2 ? Math.floor(originalChar.hp * 0.85) : originalChar.hp;
        battle.characters[id].currentHP = roundHP;
    });

    battle.turnCount = 0;
    if (battle.currentRound === 1) {
        battle.currentTurn = battle.participants[0];
    } else if (battle.currentRound === 2) {
        battle.currentTurn = battle.participants[1];
    } else if (battle.currentRound === 3) {
        battle.currentTurn = battle.participants[Math.floor(Math.random() * 2)];
    }

    startBattleTimeout(battle, 'turn', res, users);

    res.json({
        message: `${battle.isQuickRound ? "Quick Round" : `Round ${battle.currentRound}`} begins!`,
        score: `${battle.names[battle.participants[0]]}: ${battle.roundsWon[battle.participants[0]]} | ${battle.names[battle.participants[1]]}: ${battle.roundsWon[battle.participants[1]]}`,
        hpStatus: battle.currentRound <= 2 ? "Reduced by 15% for this round" : "Full health restored",
        currentTurn: battle.names[battle.currentTurn],
        skills: battle.characters[battle.currentTurn].skills.map((s, i) => ({ letter: String.fromCharCode(65 + i), name: s.name }))
    });
}

function determineFinalWinner(battle) {
    const p1 = battle.participants[0];
    const p2 = battle.participants[1];

    // Correctly assign hpLostPercentage to both players
    battle.battleStats[p1].hpLostPercentage = (battle.battleStats[p1].totalDamageTaken / battle.originalCharacters[p1].hp) * 100;
    battle.battleStats[p2].hpLostPercentage = (battle.battleStats[p2].totalDamageTaken / battle.originalCharacters[p2].hp) * 100;

    // Determine winner by rounds won
    if (battle.roundsWon[p1] > battle.roundsWon[p2]) return p1;
    if (battle.roundsWon[p2] > battle.roundsWon[p1]) return p2;

    // If tied, use HP lost percentage
    if (battle.battleStats[p1].hpLostPercentage < battle.battleStats[p2].hpLostPercentage) return p1;
    if (battle.battleStats[p2].hpLostPercentage < battle.battleStats[p1].hpLostPercentage) return p2;

    // If still tied, use total damage dealt
    if (battle.battleStats[p1].totalDamageDealt > battle.battleStats[p2].totalDamageDealt) return p1;
    if (battle.battleStats[p2].totalDamageDealt > battle.battleStats[p1].totalDamageDealt) return p2;

    // Final fallback: random
    return battle.participants[Math.floor(Math.random() * 2)];
}

function endBattle(battle, winnerId, res, users) {
    const loserId = battle.participants.find(id => id !== winnerId);
    const winner = users.find(u => u.userId === winnerId);
    const loser = users.find(u => u.userId === loserId);

    winner.coins += battle.amount * 2;
    winner.wins = (winner.wins || 0) + 1;
    winner.rank = updateRank(winner);
    loser.losses = (loser.losses || 0) + 1;
    loser.rank = updateRank(loser);

    saveUsers(users);

    res.json({
        message: `${battle.names[winnerId]} wins the battle against ${battle.names[loserId]}!`,
        winner: battle.names[winnerId],
        prize: battle.amount * 2,
        stats: {
            [battle.names[winnerId]]: battle.battleStats[winnerId],
            [battle.names[loserId]]: battle.battleStats[loserId]
        },
        roundResults: battle.roundResults
    });
}

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
