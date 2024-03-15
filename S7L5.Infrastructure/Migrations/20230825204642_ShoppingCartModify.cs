using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PizzeriaImpulsMVC.Infrastructure.Migrations
{
    public partial class ShoppingCartModify : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_ShoppingCarts_Additions_AdditionId",
                table: "ShoppingCarts");

            migrationBuilder.DropForeignKey(
                name: "FK_ShoppingCarts_Drinks_DrinkId",
                table: "ShoppingCarts");

            migrationBuilder.DropForeignKey(
                name: "FK_ShoppingCarts_Pizzas_PizzaId",
                table: "ShoppingCarts");

            migrationBuilder.DropIndex(
                name: "IX_ShoppingCarts_AdditionId",
                table: "ShoppingCarts");

            migrationBuilder.DropIndex(
                name: "IX_ShoppingCarts_DrinkId",
                table: "ShoppingCarts");

            migrationBuilder.DropIndex(
                name: "IX_ShoppingCarts_PizzaId",
                table: "ShoppingCarts");

            migrationBuilder.DropColumn(
                name: "AdditionId",
                table: "ShoppingCarts");

            migrationBuilder.RenameColumn(
                name: "PizzaId",
                table: "ShoppingCarts",
                newName: "ProductId");

            migrationBuilder.RenameColumn(
                name: "DrinkId",
                table: "ShoppingCarts",
                newName: "ProductCount");

            migrationBuilder.AlterColumn<int>(
                name: "CartId",
                table: "ShoppingCarts",
                type: "int",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AddColumn<decimal>(
                name: "Price",
                table: "ShoppingCarts",
                type: "decimal(18,2)",
                nullable: false,
                defaultValue: 0m);

            migrationBuilder.AddColumn<string>(
                name: "ProductType",
                table: "ShoppingCarts",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "UserId",
                table: "ShoppingCarts",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Price",
                table: "ShoppingCarts");

            migrationBuilder.DropColumn(
                name: "ProductType",
                table: "ShoppingCarts");

            migrationBuilder.DropColumn(
                name: "UserId",
                table: "ShoppingCarts");

            migrationBuilder.RenameColumn(
                name: "ProductId",
                table: "ShoppingCarts",
                newName: "PizzaId");

            migrationBuilder.RenameColumn(
                name: "ProductCount",
                table: "ShoppingCarts",
                newName: "DrinkId");

            migrationBuilder.AlterColumn<string>(
                name: "CartId",
                table: "ShoppingCarts",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "int");

            migrationBuilder.AddColumn<int>(
                name: "AdditionId",
                table: "ShoppingCarts",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateIndex(
                name: "IX_ShoppingCarts_AdditionId",
                table: "ShoppingCarts",
                column: "AdditionId");

            migrationBuilder.CreateIndex(
                name: "IX_ShoppingCarts_DrinkId",
                table: "ShoppingCarts",
                column: "DrinkId");

            migrationBuilder.CreateIndex(
                name: "IX_ShoppingCarts_PizzaId",
                table: "ShoppingCarts",
                column: "PizzaId");

            migrationBuilder.AddForeignKey(
                name: "FK_ShoppingCarts_Additions_AdditionId",
                table: "ShoppingCarts",
                column: "AdditionId",
                principalTable: "Additions",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_ShoppingCarts_Drinks_DrinkId",
                table: "ShoppingCarts",
                column: "DrinkId",
                principalTable: "Drinks",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_ShoppingCarts_Pizzas_PizzaId",
                table: "ShoppingCarts",
                column: "PizzaId",
                principalTable: "Pizzas",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
