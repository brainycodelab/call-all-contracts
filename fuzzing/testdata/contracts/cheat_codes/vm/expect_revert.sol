// This test ensures that the expectRevert cheatcode works as expected
interface CheatCodes {
    function expectRevert() external;

    function expectRevert(string memory) external;

    function difficulty(uint256) external;
}

contract BankContract {
    function send(uint256 amount) public pure {
        require(amount > 0, "amount must be greater than 0");
    }
}

contract TestContract {
    function test() public {
        // Obtain our cheat code contract reference.
        CheatCodes cheats = CheatCodes(
            0x7109709ECfa91a80626fF3989D68f67F5b1DD12D
        );
        BankContract bank = new BankContract();

        // Ensure expectRevert works when a cheatcode call is immediately after it
        cheats.expectRevert();
        cheats.difficulty(7);
        bank.send(0);

        // Expect a revert with a specific error message
        cheats.expectRevert("amount must be greater than 0");
        bank.send(0);
    }
}
