namespace PizzeriaImpulsMVC.Domain.Models
{
    public class ComponentPizza
    {
        public int PizzaId { get; set; }

        public  Pizza Pizza { get; set; }

        public int ComponentId { get; set; }

        public  Component Component { get; set; }
        
    }
}
