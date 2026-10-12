USE CODManager;
GO

-- Optional, idempotent local sample data. This script never deletes rows.
-- Seed login: waqtoro@example.com / waqtoro-admin / ChangeMe123!
DECLARE @CurrentSellerID INT;
DECLARE @CurrentBuyerID INT;

SELECT @CurrentSellerID = SellerID
FROM Sellers
WHERE DomainName = 'waqtoro.local';

IF @CurrentSellerID IS NULL
BEGIN
    INSERT INTO Sellers (BusinessName, WhatsAppNumber, Email, DomainName)
    VALUES ('Waqtoro Watches', '+923001234567', 'waqtoro@example.com', 'waqtoro.local');
    SET @CurrentSellerID = SCOPE_IDENTITY();
END;

SELECT @CurrentBuyerID = BuyerID
FROM Buyers
WHERE SellerID = @CurrentSellerID AND Phone = '+923339876543';

IF @CurrentBuyerID IS NULL
BEGIN
    INSERT INTO Buyers (SellerID, FullName, Phone, Address, SellerBuyerNo)
    VALUES (@CurrentSellerID, 'Ahmed Khan', '+923339876543', 'Model Town, Lahore', 1);
    SET @CurrentBuyerID = SCOPE_IDENTITY();
END;

IF NOT EXISTS (SELECT 1 FROM Orders WHERE SellerID = @CurrentSellerID AND SellerOrderNo = 1)
BEGIN
    INSERT INTO Orders (SellerID, BuyerID, SellerOrderNo, TotalAmount)
    VALUES (@CurrentSellerID, @CurrentBuyerID, 1, 15000.00);
END;

IF NOT EXISTS (SELECT 1 FROM ClientUsers WHERE Username = 'waqtoro-admin')
BEGIN
    INSERT INTO ClientUsers (SellerID, Username, PasswordHash)
    VALUES (
        @CurrentSellerID,
        'waqtoro-admin',
        'scrypt:32768:8:1$k9ERLaY103PrTtGc$beae982830f4808911de507c972cd7ac05e98a0f3093f4bd3755e540d728abb55c5b6562d154d3acb3effd0f9064dd37daa7469be19e6179e39f39c163f8bfa4'
    );
END;
GO

SELECT * FROM Orders;
SELECT * FROM vw_PendingConfirmations;
SELECT * FROM MessageLogs;
GO
