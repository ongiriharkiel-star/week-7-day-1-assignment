import express from 'express';
import bcrypt from 'bcrypt';

const app = express();
app.use(express.json());

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
