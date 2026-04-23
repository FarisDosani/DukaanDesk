USE CODManager;
GO

-- ==========================================
-- STEP 1: BULLETPROOF VIEW
-- ==========================================
CREATE OR ALTER VIEW vw_PendingConfirmations AS
SELECT 
    O.OrderID, 
    S.BusinessName, 
    B.FullName AS BuyerName, 
    B.Phone, 
    O.TotalAmount
FROM Orders O
JOIN Sellers S ON O.SellerID = S.SellerID
JOIN Buyers B ON O.BuyerID = B.BuyerID AND B.SellerID = O.SellerID
WHERE O.OrderStatus = 'Pending';
GO

-- ==========================================
-- STEP 2: BULLETPROOF TRIGGER
-- ==========================================
CREATE OR ALTER TRIGGER trg_AutoLogCreation
ON Orders
AFTER INSERT
AS
BEGIN
    DECLARE @NewOrderID INT;
    SELECT @NewOrderID = inserted.OrderID FROM inserted;

    INSERT INTO MessageLogs (OrderID, MessageContent)
    VALUES (@NewOrderID, 'System: Initial WhatsApp confirmation message queued.');
END;
GO