'use strict';
require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const readline = require('readline');
const rl = readline.createInterface({input:process.stdin,output:process.stdout});
const ask = q => new Promise(resolve=>rl.question(q,resolve));
(async()=>{
  const name=(await ask('Administrator full name: ')).trim();
  const email=(await ask('Administrator email: ')).trim().toLowerCase();
  const password=await ask('Strong password (12+ characters): ');
  if(name.length<2||!/^\S+@\S+\.\S+$/.test(email)||password.length<12){console.error('Invalid details. Use a valid email and password of at least 12 characters.');process.exitCode=1;return;}
  const db=await mysql.createConnection({host:process.env.DB_HOST,port:Number(process.env.DB_PORT||3306),database:process.env.DB_NAME,user:process.env.DB_USER,password:process.env.DB_PASSWORD});
  try{const hash=await bcrypt.hash(password,12);await db.execute('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)',[name,email,hash,'admin']);console.log(`Administrator ${email} created. Keep credentials private.`);}finally{await db.end();rl.close();}
})().catch(e=>{console.error('Could not create administrator:',e.message);process.exitCode=1;rl.close();});
