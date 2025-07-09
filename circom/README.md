# circom 入门测试教程

## 安装相应依赖

根据 [安装 - Circom 2 文档](https://docs.circom.io/getting-started/installation/) 进行安装。

## 测试用例

下面程序实现了一个乘法运算，输出为 a*b

```
pragma circom 2.1.6;

template Multiply() {
  signal input a;
  signal input b;
  signal output out;

  out <== a * b;
}

component main = Multiply();
```

将上述代码保存为 **multiply.circom** 并运行以下命令，正确编译会看到如下反馈

```
$ circom multiply.circom
template instances: 1
Everything went okay
```

运行如下命令

```
circom multiply.circom --r1cs --sym --wasm
```

> 命令结构解析:
> `--r1cs`：此选项会让编译器生成 R1CS文件。生成的文件名为 multiply.r1cs。
> `--sym`：该选项的作用是生成符号表文件，文件名为multiply.sym。此文件能建立起电路中信号和约束之间的映射关系。
> `--wasm`：此选项会使编译器生成 Wasm 代码，生成的文件存放在 **multiply_js/** 目录下。这些代码可用于生成见证，也就是满足电路约束的一组输入 / 输出值。

生成测试用例

在文件夹中创建一个 **input.json** 文件。这是一个从指定输入信号的名称到证明者将为其提供的值的映射。
文件内容如下

```
{"a": "2","b": "3"}
```

运行如下指令

```
$ node generate_witness.js multiply.wasm input.json witness.wtns
$ snarkjs wtns export json witness.wtns
$ cat witness.json
```

> 注：**generate_witness.js** 和 **multiply.wasm** 文件在 **multiply_js/** 目录下。

输出应如下

```
[
 "1",
 "6",
 "2",
 "3"
]
```

符合 R1CS 变量的预期布局，形式为[1, out, a, b]。












