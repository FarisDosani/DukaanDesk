USE CODManager;
GO

-- REPORT 1: Seller Performance
-- Shows how many orders each business has and their total revenue.
SELECT 
    S.SellerID,
    S.BusinessName, 
    COUNT(O.OrderID) AS TotalOrders, 
    COALESCE(SUM(CASE WHEN O.DeliveryStatus = 'Delivered' THEN O.TotalAmount ELSE 0 END), 0) AS DeliveredRevenue
FROM Sellers S
LEFT JOIN Orders O ON S.SellerID = O.SellerID
GROUP BY S.SellerID, S.BusinessName;

-- REPORT 2: Audit Trail
-- Shows the full history of an order, including when the WhatsApp message was "sent".
SELECT 
    O.OrderID, 
    O.OrderDate, 
    O.OrderStatus, 
    L.LogTime, 
    L.MessageContent
FROM Orders O
JOIN MessageLogs L ON O.OrderID = L.OrderID
ORDER BY L.LogTime DESC;
