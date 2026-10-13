extern alias IcedLib;
using System;
using System.Linq;
using IcedLib::Iced.Intel;

namespace BepInEx.Unity.IL2CPP.Hook;

/// <summary>
///     Moves the instructions a hook overwrites into a trampoline that runs them and continues in the original function
/// </summary>
internal static unsafe class X64Relocator
{
    private static readonly Register[] ScratchRegisters =
    [
        Register.RAX, Register.RCX, Register.RDX, Register.R8, Register.R9, Register.R10, Register.R11, Register.RBX,
    ];

    /// <summary>
    ///     Decode the instructions a patch of the given size overwrites
    /// </summary>
    /// <param name="original">Function being hooked, still unmodified</param>
    /// <param name="patchSize">Bytes the patch writes</param>
    /// <param name="error">Why the function cannot be patched</param>
    /// <returns>Instructions to relocate, null on error</returns>
    public static InstructionList Read(nint original, int patchSize, out string error)
    {
        var decoder = Decoder.Create(64, new PointerCodeReader(original), (ulong) original);
        var end = (ulong) original + (ulong) patchSize;
        var instructions = new InstructionList();
        while (decoder.IP < end)
        {
            var instruction = decoder.Decode();
            if (instruction.IsInvalid)
            {
                error = "it starts with code that cannot be decoded";
                return null;
            }

            instructions.Add(instruction);
            if (instruction.FlowControl is FlowControl.Return or FlowControl.UnconditionalBranch or FlowControl.IndirectBranch)
            {
                // A function shorter than the patch may only spill into the int3 padding before the next one
                for (var address = decoder.IP; address < end; address++)
                {
                    if (*(byte*) address != 0xCC)
                    {
                        error = $"it is shorter than the {patchSize} byte patch";
                        return null;
                    }
                }

                break;
            }
        }

        error = null;
        return instructions;
    }

    /// <summary>
    ///     Encode relocated instructions followed by a jump back into the original function
    /// </summary>
    /// <param name="instructions">Instructions from <see cref="Read" /></param>
    /// <param name="address">Where the trampoline is written</param>
    /// <param name="capacity">Most bytes the trampoline may take</param>
    /// <param name="far">Whether the trampoline is out of rel32 reach of the original function</param>
    /// <param name="error">Why the instructions could not be relocated</param>
    /// <returns>Bytes written, -1 on error</returns>
    public static int Write(InstructionList instructions, nint address, int capacity, bool far, out string error)
    {
        var block = new InstructionList();
        foreach (var instruction in instructions)
        {
            if (far && instruction.IsIPRelativeMemoryOperand)
            {
                if (!TryRewriteIPRelative(instruction, block, out error))
                    return -1;
            }
            else
            {
                block.Add(instruction);
            }
        }

        var last = instructions[instructions.Count - 1];
        if (last.FlowControl is not (FlowControl.Return or FlowControl.UnconditionalBranch or FlowControl.IndirectBranch))
            block.Add(Instruction.CreateBranch(Code.Jmp_rel32_64, last.NextIP));

        var writer = new BufferCodeWriter(address, capacity);
        if (!BlockEncoder.TryEncode(64, new InstructionBlock(writer, block, (ulong) address), out error, out _))
            return -1;

        return writer.Length;
    }

    /// <summary>
    ///     Rewrite an instruction that reads or writes memory relative to its own address so it works from anywhere.
    ///     The address goes into a register the instruction does not use, saved around it on the stack
    /// </summary>
    /// <param name="instruction">Instruction with a RIP relative memory operand</param>
    /// <param name="block">List the replacement is added to</param>
    /// <param name="error">Why the instruction cannot be rewritten</param>
    /// <returns>True when the replacement was added</returns>
    private static bool TryRewriteIPRelative(in Instruction instruction, InstructionList block, out string error)
    {
        var target = instruction.IPRelativeMemoryAddress;
        if (instruction.Code is Code.Lea_r64_m or Code.Lea_r32_m)
        {
            var load = instruction.Code == Code.Lea_r64_m
                ? Instruction.Create(Code.Mov_r64_imm64, instruction.Op0Register, target)
                : Instruction.Create(Code.Mov_r32_imm32, instruction.Op0Register, (uint) target);
            load.IP = instruction.IP;
            block.Add(load);
            error = null;
            return true;
        }

        var used = new InstructionInfoFactory().GetInfo(instruction).GetUsedRegisters()
                                               .Select(register => register.Register.GetFullRegister())
                                               .ToHashSet();

        // Pushing the scratch register moves the stack, which an instruction using it or branching through memory would see
        if (instruction.FlowControl != FlowControl.Next || used.Contains(Register.RSP))
        {
            error = $"its {instruction} reads memory near the original function and cannot run from far away";
            return false;
        }

        var scratch = ScratchRegisters.First(register => !used.Contains(register));
        var push = Instruction.Create(Code.Push_r64, scratch);
        push.IP = instruction.IP;
        block.Add(push);
        block.Add(Instruction.Create(Code.Mov_r64_imm64, scratch, target));

        var moved = instruction;
        moved.IP = 0;
        moved.MemoryBase = scratch;
        moved.MemoryDisplacement64 = 0;
        moved.MemoryDisplSize = 0;
        block.Add(moved);
        block.Add(Instruction.Create(Code.Pop_r64, scratch));

        error = null;
        return true;
    }

    private sealed class PointerCodeReader(nint start) : CodeReader
    {
        private int offset;

        public override int ReadByte() => ((byte*) start)[offset++];
    }

    private sealed class BufferCodeWriter(nint start, int capacity) : CodeWriter
    {
        public int Length { get; private set; }

        public override void WriteByte(byte value)
        {
            if (Length >= capacity)
                throw new InvalidOperationException("Trampoline is larger than its reserved space");

            ((byte*) start)[Length++] = value;
        }
    }
}
