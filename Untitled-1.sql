SELECT * from ClientUsers;
UPDATE ClientUsers SET IsLocked = 0, FailedAttempts = 0, LastFailedAt = NULL 
WHERE UserID = 1; 