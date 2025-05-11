# Dromedary

We have a binary. Its behavior is simple:

```
$ ./dromedary 
What's a dromedary that has two bosses instead of only one? Tell me: test
Nope, sorry!
```

We'll try to find the correct answer here. Having no source code to analyze, we have to decompile the program. I used Ghidra for this. The main function looks a bit weird:

```c
int main(int argc,char **argv)
{
  caml_main(argv);
                    /* WARNING: Subroutine does not return */
  caml_do_exit(0);
}
```

Indeed, it is not a regular C function; the program was coded in Caml, hence the pun with the challenge name. In order to find the program instructions for the main function, we have to dive in... here is the chain of functions we have to follow in order to get there:

```
caml_main -> caml_startup_common -> caml_start_program -> caml_program -> camlDune__exe__Main__entry
```

Once we find the "real" main function, we can analyze it:

```c
void camlDune__exe__Main__entry(void)

{
  value val;
  value val_00;
  undefined8 uVar1;
  long lVar2;
  long extraout_RAX;
  undefined8 uVar3;
  value extraout_RAX_00;
  undefined8 extraout_RAX_01;
  undefined8 uVar4;
  undefined8 extraout_RAX_02;
  value s2;
  undefined8 *puVar5;
  value *fp;
  undefined8 uVar6;
  value vVar7;
  long unaff_R14;
  long unaff_R15;
  undefined1 auVar8 [16];
  
  lVar2 = DAT_0032b618;
  uVar4 = *(undefined8 *)(DAT_002cdc30 + 0x10);
  val = *(value *)(DAT_0032b618 + 0xd0);
  val_00 = *(value *)(DAT_0032b618 + 200);
  uVar6 = *(undefined8 *)(DAT_0032b618 + 0xc0);
  uVar1 = *(undefined8 *)(DAT_0032b618 + 0xb8);
  vVar7 = val_00;
  auVar8 = caml_allocN();
  puVar5 = (undefined8 *)(unaff_R15 + -0x20);
  *(undefined8 *)(unaff_R15 + -0x28) = 0x1000;
  *puVar5 = auVar8._8_8_;
  *(undefined8 *)(unaff_R15 + -0x18) = uVar6;
  *(value *)(unaff_R15 + -0x10) = vVar7;
  *(value *)(unaff_R15 + -8) = val;
  uVar6 = *(undefined8 *)(auVar8._0_8_ + 0xb0);
  *(undefined8 *)(unaff_R15 + -0x50) = 0x10f7;
  *(undefined8 *)(unaff_R15 + -0x48) = camlDune__exe__Main__reset_740;
  *(undefined8 *)(unaff_R15 + -0x40) = 0x100000000000005;
  *(undefined8 **)(unaff_R15 + -0x38) = puVar5;
  *(undefined8 *)(unaff_R15 + -0x30) = uVar6;
  fp = (value *)(unaff_R15 + -0x60);
  *(undefined8 *)(unaff_R15 + -0x68) = 0x800;
  *fp = 1;
  *(undefined8 *)(unaff_R15 + -0x58) = 1;
  *(undefined8 *)(unaff_R15 + -0x88) = 0xcf7;
  *(code **)(unaff_R15 + -0x80) = camlDune__exe__Main__aux_886;
  *(undefined8 *)(unaff_R15 + -0x78) = 0x100000000000005;
  *(value **)(unaff_R15 + -0x70) = fp;
  *(undefined8 *)(unaff_R15 + -0xa0) = 0x800;
  *(undefined8 *)(unaff_R15 + -0x98) = &camlSpectrum__const_immstring_133;
  *(value *)(unaff_R15 + -0x90) = *fp;
  caml_modify(fp,(value)(unaff_R15 + -0x98));
  *(long *)(unaff_R15 + -0x58) = *(long *)(unaff_R15 + -0x58) + 2;
  camlStdlib__Seq__empty_41();
  if (extraout_RAX != 1) {
    vVar7 = *fp;
    uVar3 = caml_alloc2();
    *(undefined8 *)(unaff_R15 + -0xa0) = 0x800;
    *(undefined8 *)(unaff_R15 + -0x98) = uVar3;
    *(value *)(unaff_R15 + -0x90) = vVar7;
    caml_modify(fp,(value)(unaff_R15 + -0x98));
    *(long *)(unaff_R15 + -0x58) = *(long *)(unaff_R15 + -0x58) + 2;
    camlDune__exe__Main__aux_886();
  }
  caml_allocN();
  *(undefined8 *)(unaff_R15 + -0xe0) = 0x1cf7;
  *(undefined8 *)(unaff_R15 + -0xd8) = camlDune__exe__Main__mark_open_stag_761;
  *(undefined8 *)(unaff_R15 + -0xd0) = 0x100000000000005;
  *(undefined8 *)(unaff_R15 + -200) = uVar4;
  *(value **)(unaff_R15 + -0xc0) = fp;
  *(undefined8 **)(unaff_R15 + -0xb8) = puVar5;
  *(undefined8 *)(unaff_R15 + -0xb0) = uVar6;
  *(undefined8 *)(unaff_R15 + -0xa8) = uVar1;
  *(undefined8 *)(unaff_R15 + -0x100) = 0xcf7;
  *(undefined8 *)(unaff_R15 + -0xf8) = camlDune__exe__Main__mark_close_stag_790;
  *(undefined8 *)(unaff_R15 + -0xf0) = 0x100000000000005;
  *(value **)(unaff_R15 + -0xe8) = fp;
  caml_modify((value *)(lVar2 + 0xb8),(value)(unaff_R15 + -0xd8));
  caml_modify((value *)(lVar2 + 0xc0),(value)(unaff_R15 + -0xf8));
  caml_modify((value *)(lVar2 + 200),val_00);
  caml_modify((value *)(lVar2 + 0xd0),val);
  *(undefined8 *)(lVar2 + 0xb0) = 3;
  camlDune__exe__Main__reset_ppf_162 = (undefined8 *)(unaff_R15 + -0x48);
  camlCamlinternalFormat__make_printf_4961();
  caml_c_call(camlStdlib__Pccall_1846);
  puVar5 = *(undefined8 **)(unaff_R14 + 8);
  camlStdlib__input_line_1013();
  camlDune__exe__Main__user_input_158 = extraout_RAX_00;
  camlStdlib__Bytes__make_245();
  camlStdlib__List__map_462();
  uVar4 = caml_alloc2();
  camlDune__exe__Main__apply_arg_156 = puVar5 + 1;
  *puVar5 = 0x800;
  *camlDune__exe__Main__apply_arg_156 = extraout_RAX_01;
  puVar5[2] = uVar4;
  camlStdlib__String__sum_lengths_277();
  caml_c_call(extraout_RAX_02);
  camlStdlib__String__unsafe_blits_311();
  camlDune__exe__Main__processed_154 = s2;
  camlDune__exe__Main__cond_153 = caml_string_equal(camlDune__exe__Main__user_input_158,s2);
  if (camlDune__exe__Main__cond_153 == 1) {
    camlCamlinternalFormat__make_printf_4961();
  }
  else {
    camlCamlinternalFormat__make_printf_4961();
  }
  lVar2 = DAT_0032b618;
  uVar4 = camlDune__exe__Main__reset_ppf_162[3];
  camlStdlib__Format__pp_flush_queue_1605();
  (*(code *)**(undefined8 **)(lVar2 + 0x88))();
  *(undefined8 *)(DAT_0032b618 + 0xb0) = uVar4;
  camlStdlib__Format__pp_set_formatter_stag_functions_1511();
  return;
}
```

That looks.. unnecessarily complex. But still, we can extract some interesting information from this code. There seems to be a call to printf through a wrapper named `camlCamlinternalFormat__make_printf_4961`, and some other calls.. but the most interesting part is the answer validation.
A call to `caml_string_equal`, which is the equivalent for the traditional `strcmp`, is done, comparing the user input with some `s2` label. We can easily understand that the answer we're looking for is in that s2 label at runtime. Using the GDB debugger, we can find the address for the string comparison function, and put a breakpoint there:

```
(gdb) info address caml_string_equal
Symbol "caml_string_equal" is a function at address 0x5555556cf4a0.
(gdb) b *0x5555556cf4a0
Breakpoint 2 at 0x5555556cf4a0: file str.c, line 276.
```

Once we reach the breakpoint, we can print the contents of s2, and we have our flag!

```
(gdb) r
What's a dromedary that has two bosses instead of only one? Tell me: whatever 

Breakpoint 2, caml_string_equal (s1=140737350800592, s2=140737350799552) at str.c:276
(gdb) x/s s2
0x7ffff7cd10c0: "RM{1t'5_c4113d_4_c4m31!!}"
```
