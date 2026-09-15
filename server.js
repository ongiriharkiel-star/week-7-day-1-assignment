import express from 'express';
import bcrypt from 'bcrypt';

const app = express();
app.use(express.json());

const crypto = require('crypto');

const resetToken = new Map();

const users = [];

app.post('/api/auth/register', async (req, res) => {
  try {
    const {email, password, name } = req.body;

    //1. basic presence check
    if (!email || !password || !name) {
      return res.status(400).json({error: 'Email,password, and name are required'});
    }
    const normalizedEmail = email.toLowerCase().trim();
    const trimmedName = name.trim();

    //2.Email format validation (@ and domain check)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({error: 'invalid email format' });
    }

    //3. Name length validation (atleast 2 trimmed characters)
    if (trimmedName.length < 2) {
      return res.status(400).json({ error: 'Name must be atleast 2 characters long' });
    }

    //4. password strength validation (min 8 chars, 1 uppercase, 1 number)
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long, contain at least one uppercase letter and one number' });
    }
    
    //5.Case-insensitive duplicate email check
    const existingUser = users.find(u => u.email.toLowerCase() === normalizedEmail);
    if (existingUser) {
      return res.status(409).json({error: 'Email already registered' })
    }

    //6. secure hashing with costfactor 10
    const passwordHash = await bcrypt.hash(password, 10);

    //7 user object creation and storage
    const newUser = {
      id: users.length + 1,
      email: normalizedEmail,
      name: trimmedName,
      passwordHash
    };
    users.push(newUser);

    //8. return 201 created (excluding passwordhash)
    return res.status(201).json({
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name
      }
    });
    
  }catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({error: 'Internal server error' });
  }
});

app.listen(3000, () => {
  console.log('server running on http://localhost:3000');
});

//login with ratelimiting
const loginattempts = new Map();

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({error: 'Email and password are required'});
    }

    const normalizedEmail = email.toLowerCase().trim();
    const now = new Date();

    //fetch existing attempt history or set default
    let record = loginattempts.get(normalizedEmail) || { count: 0, lockedUntil: null };
    
    //check if account is locked
    if (record.lockedUntil && record.lockedUntil > now) {
      const remainingMinutes = Math.ceil((record.lockedUntil - now) / 60000);
      return res.status(429).json({error: `Account locked. Try again in ${remainingMinutes} minutes`});
  }

  //Reset count if lock period has passed
  if (record.lockedUntil && record.lockedUntil <=now) {
    record = { count: 0, lockedUntil: null };
    loginattempts.set(normalizedEmail, record);
  }

    const user = users.find(u => u.email === normalizedEmail);
    const passwordMatches = user && await bcrypt.compare(password, user.passwordHash);

    if (!passwordMatches) {
      record.count += 1;

      if (record.count >= 5) {
        record.lockedUntil = new Date(now.getTime() + 15 * 60 * 1000);
      }

      loginattempts.set(normalizedEmail, record);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    loginattempts.delete(normalizedEmail);
    return res.status(200).json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

//forgot password endpoint
app.post('/api/auth/forgot-pssword', async (req, res) => {
  try {
    const {email} = req.body;

    if (!email) {
      return res.status(400).json({error: 'Email is required'});
    }
  
    const normalizedEmail = email.toLowerCase().trim();
    const user = users.find(u => u.email === normalizedEmail);

    //to prevent email enumeration, always return success message even if user doesn't exist
    if (!user) {
      return res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    }

    //generate random 32-byte hex token 
    const token = crypto.randomBytes(32).toString('hex');

    //set 1 hr expiration for the token
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

    //save token to memory
    resetTokens.set(token, { email: normalizedEmail, expiresAt });

    //simulate sending an email by logging to console
    console.log(`Password reset link for ${normalizedEmail}: http://localhost:3000/reset-password?token=${token}`);

    return res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

//reset-password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    //check if token exists in store
    const tokenData = resetTokens.get(token);
    if (!tokenData) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    //validate token expiration
    const now = new Date();
    if (tokenRecord.espiresAt < now) {
      //cleanup expired token
      resetTokens.delete(token);
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    //validate new password strength
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long, contain at least one uppercase letter and one number' });
    }

    //find target user
    const user = users.find(u => u.email ===tokenRecord.email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid token' });
    }

    //hash new password
    const salt = await bcrypt.genSalt(10);
    user.passwordHash = await bcrypt.hash(newPassword, salt);

    //invalidate token (single-use)
    resetTokens.delete(token);

    return res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({error: 'password reset failed'});
  }
})


