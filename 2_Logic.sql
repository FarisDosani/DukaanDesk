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
    SET NOCOUNT ON;

    INSERT INTO MessageLogs (OrderID, MessageContent)
    SELECT OrderID, 'System: Initial WhatsApp confirmation message queued.'
    FROM inserted;
END;
GO

-- Organization IDs and their legacy SellerID mappings are permanent tenant identities.
-- Future lifecycle work should add status/soft-delete fields instead of changing these keys.
CREATE OR ALTER TRIGGER trg_Organizations_ImmutableIdentity
ON Organizations
AFTER UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted)
        THROW 50012, 'Organizations cannot be deleted; use a future lifecycle status instead.', 1;

    IF UPDATE(OrganizationID) OR UPDATE(LegacySellerID)
        THROW 50013, 'OrganizationID and LegacySellerID are immutable.', 1;
END;
GO
