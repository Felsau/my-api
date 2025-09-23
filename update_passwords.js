// update_passwords.js
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const db = new sqlite3.Database('./app_full.db');
const saltRounds = 10;

// --- กำหนดรหัสผ่านใหม่ที่นี่ ---
const usersToUpdate = [
  { email: 'owner@email.com', newPassword: '1234' },
  { email: 'tenant_a201@email.com', newPassword: '1234' },
  { email: 'tenant_b102@email.com', newPassword: '1234' },
  { email: 'tenant_c305@email.com', newPassword: '1234' },
  { email: 'tenant_a202@email.com', newPassword: '1234' }
];
// --------------------------------

db.serialize(() => {
  const stmt = db.prepare("UPDATE users SET password = ? WHERE email = ?");

  console.log('Starting password update...');

  usersToUpdate.forEach(user => {
    const hashedPassword = bcrypt.hashSync(user.newPassword, saltRounds);
    stmt.run(hashedPassword, user.email, function(err) {
      if (err) {
        return console.error(`Error updating password for ${user.email}:`, err.message);
      }
      if (this.changes > 0) {
        console.log(`Successfully updated password for ${user.email}`);
      } else {
        console.log(`User not found: ${user.email}`);
      }
    });
  });

  stmt.finalize((err) => {
    if (err) {
      return console.error('Error finalizing statement:', err.message);
    }
    console.log('Password update process finished.');
  });
});

db.close((err) => {
  if (err) {
    return console.error('Error closing database:', err.message);
  }
  console.log('Database connection closed.');
});