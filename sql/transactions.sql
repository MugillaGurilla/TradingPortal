CREATE TABLE transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    company TEXT NOT NULL,
    of_type TEXT NOT NULL,
    shares INTEGER NOT NULL,
    price INTEGER NOT NULL,
    time_bought DATETIME,
    user TEXT NOT NULL);
