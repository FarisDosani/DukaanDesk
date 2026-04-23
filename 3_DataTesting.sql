USE CODManager;
GO

-- ==========================================
-- STEP 1: WIPE OLD DATA
-- ==========================================
-- Delete in reverse order of relationships to avoid Foreign Key errors
DELETE FROM MessageLogs;
DELETE FROM Orders;
DELETE FROM ClientUsers;
DELETE FROM Buyers;
DELETE FROM Sellers;
GO

-- ==========================================
-- STEP 2: INSERT FRESH MOCK DATA (DYNAMICALLY)
-- ==========================================
-- Create variables to hold the IDs so we never have to guess them
DECLARE @CurrentSellerID INT;
DECLARE @CurrentBuyerID INT;

-- 1. Insert Seller
INSERT INTO Sellers (BusinessName, WhatsAppNumber, Email, DomainName) 
VALUES ('Waqtoro Watches', '+923001234567', 'waqtoro@example.com', 'waqtoro.local');
-- Instantly capture the ID that SQL Server just assigned to Waqtoro
SET @CurrentSellerID = SCOPE_IDENTITY(); 

-- 2. Insert Buyer
INSERT INTO Buyers (SellerID, FullName, Phone, Address, SellerBuyerNo) 
VALUES (@CurrentSellerID, 'Ahmed Khan', '+923339876543', 'Model Town, Lahore', 1);
-- Instantly capture Ahmed's new ID
SET @CurrentBuyerID = SCOPE_IDENTITY(); 

-- 3. Insert Order using those captured IDs!
INSERT INTO Orders (SellerID, BuyerID, SellerOrderNo, TotalAmount) 
VALUES (@CurrentSellerID, @CurrentBuyerID, 1, 15000.00);

-- 4. Insert Portal User (demo password for development only)
INSERT INTO ClientUsers (SellerID, Username, PasswordHash)
VALUES (@CurrentSellerID, 'waqtoro-admin', 'admin123');
GO

-- ==========================================
-- STEP 3: VIEW THE RESULTS
-- ==========================================
SELECT * FROM Orders;
SELECT * FROM vw_PendingConfirmations;
SELECT * FROM MessageLogs;
GO