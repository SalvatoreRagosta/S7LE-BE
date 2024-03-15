using System.ComponentModel.DataAnnotations;

namespace PizzeriaImpulsMVC.Domain.Models;

public class Order
{
    public int Id { get; set; }

    [Required]
    [MaxLength(50)]
    public string UserName { get; set; }

    [Required]
    [MaxLength(50)]
    public string FirstName { get; set; }

    [Required]
    [MaxLength(50)]
    public string LastName { get; set; }

    [Required]
    [MaxLength(50)]
    public string City { get; set; }

    [Required]
    [MaxLength(50)]
    public string Street { get; set; }

    [Required]
    public int HomeNumber { get; set; }
    
    [Required]
    public int ApartmentNumber { get; set; }

    public string? PhoneNumber { get; set; }

    [Required]
    public decimal Total { get; set; }

    [Required]
    public DateTime OrderDate { get; set; }

    public List<OrderDetail> OrderDetails { get; set; }

}