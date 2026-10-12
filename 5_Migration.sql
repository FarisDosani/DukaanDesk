-- Non-destructive hardening migration for an existing CODManager database.
-- Back up the database and review the preflight rules before running manually.
USE CODManager;
GO

SET XACT_ABORT ON;

BEGIN TRY
    BEGIN TRANSACTION;

    IF EXISTS (
        SELECT 1
        FROM Orders
        WHERE TotalAmount IS NULL
           OR TotalAmount <= 0
           OR OrderStatus IS NULL
           OR OrderDate IS NULL
           OR OrderStatus NOT IN ('Pending', 'Confirmed', 'Cancelled')
           OR (DeliveryStatus IS NOT NULL AND DeliveryStatus NOT IN ('Pending', 'Delivered', 'Returned by buyer'))
           OR NOT (
               (OrderStatus = 'Pending' AND DeliveryStatus IS NULL)
               OR (OrderStatus = 'Confirmed' AND DeliveryStatus IS NOT NULL)
               OR (OrderStatus = 'Cancelled' AND DeliveryStatus IS NULL)
           )
    )
        THROW 50002, 'Order data violates the hardened state rules. No migration changes were applied.', 1;

    IF EXISTS (
        SELECT 1
        FROM Orders O
        INNER JOIN Buyers B ON B.BuyerID = O.BuyerID
        WHERE B.SellerID <> O.SellerID
    )
        THROW 50003, 'Cross-seller order/buyer rows exist. No migration changes were applied.', 1;

    ALTER TABLE Orders ALTER COLUMN OrderStatus NVARCHAR(20) NOT NULL;
    ALTER TABLE Orders ALTER COLUMN OrderDate DATETIME2 NOT NULL;

    IF NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UQ_Buyers_SellerBuyerIdentity')
        ALTER TABLE Buyers ADD CONSTRAINT UQ_Buyers_SellerBuyerIdentity UNIQUE (SellerID, BuyerID);

    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Orders_PositiveAmount')
        ALTER TABLE Orders WITH CHECK ADD CONSTRAINT CK_Orders_PositiveAmount CHECK (TotalAmount > 0);

    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Orders_AllowedOrderStatus')
        ALTER TABLE Orders WITH CHECK ADD CONSTRAINT CK_Orders_AllowedOrderStatus
            CHECK (OrderStatus IN ('Pending', 'Confirmed', 'Cancelled'));

    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Orders_AllowedDeliveryStatus')
        ALTER TABLE Orders WITH CHECK ADD CONSTRAINT CK_Orders_AllowedDeliveryStatus
            CHECK (DeliveryStatus IN ('Pending', 'Delivered', 'Returned by buyer'));

    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Orders_StateConsistency')
        ALTER TABLE Orders WITH CHECK ADD CONSTRAINT CK_Orders_StateConsistency CHECK (
            (OrderStatus = 'Pending' AND DeliveryStatus IS NULL)
            OR (OrderStatus = 'Confirmed' AND DeliveryStatus IS NOT NULL)
            OR (OrderStatus = 'Cancelled' AND DeliveryStatus IS NULL)
        );

    IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_Orders_SellerBuyer')
        ALTER TABLE Orders WITH CHECK ADD CONSTRAINT FK_Orders_SellerBuyer
            FOREIGN KEY (SellerID, BuyerID) REFERENCES Buyers(SellerID, BuyerID);

    COMMIT TRANSACTION;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    THROW;
END CATCH;
GO

-- PasswordHash rows containing legacy plaintext are upgraded to Werkzeug scrypt
-- hashes by app.py after a successful login. No credential values are printed here.
